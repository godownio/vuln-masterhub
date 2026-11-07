---
id: crypto-prng-lcg-known-modulus-xor-keystream
title: 已知模数 2^32 的 LCG：前三输出恢复 A/C/seed，输出作 XOR keystream 解密
type: scenario
domain: crypto
path: crypto/prng
technique: lcg-known-modulus-keystream
tags:
- crypto
- prng
- lcg
- xor-keystream
- parameter-recovery
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:31:37+08:00'
  notes: 已对照原文核对：M=2^32、前 8 个输出公开、A=(x3-x2)/(x2-x1)、C=x2-A*x1、seed=(x1-C)/A、前 8 输出回代验证、跳过前 8 取低字节作 XOR keystream、flag VishwaCTF{s33ds_4r3_n3v3r_s4f3_1ns1d3_pr1m3s_4nd_n01s3} 均一致（已手工核对公式）。未验证点：PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/crypto/prng/crypto-prng-lcg-known-modulus-xor-keystream/
draft: false
kb_aliases:
- The Curator
- LCG 已知模数
- LCG keystream
- 前三输出恢复参数
---

## 一句话结论

当 LCG 的模数已知（如 `2^32`）且前 8 个输出公开时，用前三个输出即可解出乘数 `A`、增量 `C` 与种子 `seed`；按同一递推生成后续输出，跳过已公开的前 8 个，取低字节作 XOR keystream，即可直接解密 `encrypted_flag`。

## 原理

- LCG 递推：`x_{n+1} = (A·x_n + C) mod M`。已知 `M=2^32` 时：
  - `d1 = x2 - x1`，`d2 = x3 - x2`；
  - `A = d2 · d1^{-1} mod M`；
  - `C = x2 - A·x1 mod M`；
  - `seed = (x1 - C) · A^{-1} mod M`。
- 只要 `gcd(d1, M)=1`（d1 为奇数）即可求逆；否则需要更多输出或分解因子。
- 验证前 8 个公开输出后，按同一递推继续生成；密文与“第 9 个输出起”的 keystream 逐字节 XOR。
- 安全性完全依赖种子/参数保密；输出一旦泄露，线性递推使后续全部可预测。

## 触发条件

- 已知 LCG 形式与模数（本题 `M=2^32`）。
- 至少 3 个连续完整输出（本题公开前 8 个）。
- 后续输出被用作 XOR keystream（取低字节或其他固定截断）。

## 利用步骤

1. 取前三个输出 `x1,x2,x3`，计算 `d1,d2`。
2. 求 `A = d2 * inv(d1, M) % M`，`C = (x2 - A*x1) % M`，`seed = (x1 - C) * inv(A, M) % M`。
3. 用前 8 个输出回代验证参数。
4. 从 seed 继续生成 `8 + len(ct)` 个输出，跳过前 8 个公开值。
5. 取每个输出的低字节与密文 XOR，得到明文。

## PoC

```python
M = 2**32
outs = [980887876, 699919547, 2058135724, 3888182547,
        3474875028, 107192043, 215891708, 1328661059]
ct = bytes.fromhex("b2723f1b432adff7c2009fe0e7cf4f5c10a9bf6c1a38aa50b6645fa7725823f20ae8fd9787946c5135965f200b1fd2e7fb353c8287b821")

x1, x2, x3 = outs[:3]
A = ((x3 - x2) * pow(x2 - x1, -1, M)) % M
C = (x2 - A * x1) % M
seed = ((x1 - C) * pow(A, -1, M)) % M

x = seed
stream = []
for _ in range(8 + len(ct)):
    x = (A * x + C) % M
    stream.append(x)
keystream = bytes(v & 0xff for v in stream[8:8+len(ct)])
print(bytes(c ^ k for c, k in zip(ct, keystream)).decode())
```

## 变体与关联

- 模数未知时用差分 gcd 恢复（见 [[crypto-prng-lcg-parameter-recovery-delta-gcd]]）。
- 输出被截断/取高位时需 HNP/格方法（见 [[crypto-prng-truncated-lcg-coppersmith-lattice-cvp]]）。
- 关联：[[ctf-crypto-xor-keystream-reuse-known-plaintext]]（XOR 流复用）。

## 检测与防御

- 不要用 LCG 生成密钥流；使用 CSPRNG 或流密码。
- 即使种子随机，输出泄露也会导致状态可预测；输出应经过加密/哈希。
- 检测：连续整数序列呈线性递推、密文长度与 PRNG 输出对齐。
