---
id: crypto-prng-conditional-lfsr-sat-onehot-counter
title: 条件更新 LFSR 的 SAT 求解：前缀和 one-hot 计数器 + 翻转约束
type: scenario
domain: crypto
path: crypto/prng
technique: conditional-lfsr-sat-onehot-prefix-counter
tags:
- crypto
- prng
- lfsr
- sat
- pycryptosat
- stream-cipher
- state-recovery
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:19:41+08:00'
  notes: 已对照原文核对：两个 64 位 LFSR、lfsr2 仅在 lfsr1 输出 1 时更新、output[t]=z_{sum(c_0..c_t)}、c_t/z_j 为 seed 的 GF(2) 线性函数、one-hot 前缀计数器、翻转⇒当轮更新约束、seed 最高位为 1、md5(str(seed)) 作 AES key、pycryptosat 增量枚举与 min_flips=26 实例筛选、案例 seed/secret 均一致。未验证点：PoC 为骨架，未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/crypto/prng/crypto-prng-conditional-lfsr-sat-onehot-counter/
draft: false
kb_aliases:
- polarisCTF ocean
- LFSR1/LFSR2
- 条件更新 LFSR
- one-hot 计数器
- pycryptosat
- 翻转约束
- min_flips
---

## 一句话结论

两个 64 位 LFSR 中，`lfsr2` 只在 `lfsr1` 输出为 1 时更新，最终输出 `output[t] = z_{sum(c_0..c_t)}`；`c_t` 与 `z_j` 都是 seed 的 GF(2) 线性函数，非线性只剩“前缀和选择哪个 `z_j`”。用 SAT 表示 64 个 seed 位、XOR 约束的 `c_t/z_j`、one-hot 前缀计数器和“输出翻转 ⇒ 当轮必须更新”的约束，即可在 60 秒内恢复 seed 并解密。

## 原理

- **两个 LFSR**：`lfsr1` 每轮正常更新并输出控制位 `c_t`；`lfsr2` 只在 `c_t=1` 时更新。最终 64 位输出的第 t 位是 `z_{S_t}`，其中 `S_t = c_0 + c_1 + ... + c_t` 是到第 t 轮为止 `lfsr2` 的更新次数。
- **线性性**：LFSR 的状态转移和输出都是 GF(2) 线性的，因此每个 `c_t` 和每个 `z_j`（`lfsr2` 更新 j 次后的输出位）都可写成 64 个 seed 位的 XOR。
- **非线性来源**：只有“根据前缀和 `S_t` 选择 `z_{S_t}`”这一步是非线性的；把 `S_t` 用 one-hot 计数器编码后，可用 SAT 处理。
- **SAT 编码**：
  - 64 个布尔变量表示 seed；`seed` 由 `getRandomNBitInteger(64)` 生成，最高位恒为 1，加约束。
  - 每个 `c_t`、`z_j` 用 `add_xor_clause` 表示成 seed 的线性函数。
  - `cnt[t][j]` 表示“第 t 轮结束后 `lfsr2` 更新了 j 次”；`cnt[0][1]=c_0`，之后 `cnt[t][j] = c_t ? cnt[t-1][j-1] : cnt[t-1][j]`（用 ITE/AND 子句展开）。
  - `output[t] = z_j`：对每个 `cnt[t][j]=1`，加子句强制 `z_j == output[t]`。
- **翻转约束**：若 `output[t] != output[t-1]`，说明第 t 轮 `lfsr2` 必须更新，即 `c_t=1`。对随机输出，这条约束能固定大量控制位，显著加速求解。
- **多解与枚举**：满足约束的 seed 可能不止一个，需用 AES 解密验证 `fakeflag{...}` 格式；用 pycryptosat 增量求解，每次加 blocking clause 求下一个模型，避免重新建模。
- **实例筛选**：不同实例的翻转次数不同，翻转越多约束越强；只选择 `min_flips >= 26` 的实例，失败则重连换实例。
- **为什么可行**：64 位 seed 的搜索空间是 2^64，但 SAT 利用线性结构和前缀和约束把它压到可解；60 秒内通常能枚举前若干个候选并命中正确 seed。

## 触发条件

- 目标使用两个 LFSR，其中一个条件更新，另一个正常更新；输出位是条件 LFSR 的当前位。
- `seed` 为 64 位且最高位已知（如 `getRandomNBitInteger(64)` 最高位为 1）。
- 攻击者拿到 `mask1`、`mask2`、64 位 `output` 与 `AES_ECB(md5(str(seed)), secret)` 密文。
- 有 SAT 求解器（pycryptosat/CryptoMiniSat）与 AES 验证逻辑。
- 时间限制内允许枚举多个候选/重连。

## 利用步骤

1. 从服务端读取 `mask1`、`mask2`、`output`、`enc`；计算 `output` 的相邻位翻转次数，低于阈值（如 26）则重连换实例。
2. 预计算 `lfsr1` 的 64 个 `c_t` 线性行与 `lfsr2` 的 65 个 `z_j` 线性行（`z_0..z_64`）。
3. 建立 SAT：seed 变量 + 最高位 1；`c_t/z_j` 的 XOR 约束；`cnt[t][j]` 的 one-hot 转移；`output[t]=z_j` 的蕴含；翻转约束 `output[t]!=output[t-1] ⇒ c_t=1`。
4. 求解模型，取 seed；用 `simulate(mask1,mask2,seed)` 复核 `output`。
5. 用 `md5(str(seed))` 做 AES-ECB 解密，检查明文是否为 `fakeflag{32hex}`；失败则加 blocking clause 求下一个模型。
6. 命中后提交/输出明文；若枚举上限内无解，重连换实例。

## PoC

```python
from pycryptosat import Solver

# 64 个 seed 位，最高位固定 1
# c_t = XOR(seed & mask1_row_t)
# z_j = XOR(seed & mask2_row_j)
# cnt[t][j]：第 t 轮后 lfsr2 更新 j 次
# cnt[0][1] = c_0；cnt[t][j] = c_t ? cnt[t-1][j-1] : cnt[t-1][j]
# 对每个 cnt[t][j]=1：z_j == output[t]
# 若 output[t] != output[t-1]：c_t = 1

solver = Solver()
# ... 建模 ...
sat, model = solver.solve()
seed = bits_to_int(model, seed_vars)

# 复核
assert simulate(mask1, mask2, seed) == output

# AES 验证；失败则 blocking clause 求下一个
key = hashlib.md5(str(seed).encode()).digest()
pt = unpad(AES.new(key, AES.MODE_ECB).decrypt(enc), 16)
```

```text
# 案例：flips=26，candidate 1 命中
# seed = 9582451577998823576
# secret = fakeflag{997ab6dca75a1892802d61f43f6a0c9c}
```

## 变体与关联

- 条件变体：`lfsr2` 可在 `c_t=0` 时更新、按多比特控制、按计数器阈值更新；SAT 编码相应调整。
- 求解器变体：pycryptosat 增量求解、CryptoMiniSat、Z3；翻转约束和 one-hot 计数器是通用加速手段。
- 关联：[[ctf-crypto-lfsr-known-plaintext-state-recovery]]（已知明文线性方程）、[[crypto-prng-mt19937-untemper-state-recovery-predict]]（MT19937 状态恢复）、[[crypto-prng-lcg-parameter-recovery-delta-gcd]]（LCG 参数恢复）。

## 检测与防御

- 检测：输出呈现 LFSR 线性结构；同一 seed 驱动两个寄存器；相邻输出翻转与控制位相关；AES 密钥由 `md5(str(seed))` 派生。
- 防御：不要用 LFSR/线性反馈寄存器生成密钥或认证材料；使用 CSPRNG/流密码（ChaCha20、AES-CTR）并配合 MAC；seed 使用高熵随机数，不要只依赖 64 位。
- 加固：对密钥派生使用 HKDF；限制输出样本数量；对异常/多候选请求做速率限制；定期轮换密钥。
