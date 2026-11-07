---
id: crypto-rsa-crt-multi-modulus-high-bits-coppersmith-low-bits
title: RSA 高位分片泄漏：多个小模数 CRT 还原 p 高 704 位，Coppersmith 小根恢复低 320 位
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-crt-multi-modulus-high-bits-coppersmith
aliases:
- Broken Transcript
- RSA 高位泄漏 + CRT
- 多模数 CRT 恢复 p 高位
- Coppersmith 恢复低位
- 部分密钥暴露
tags:
- rsa
- partial-key-exposure
- coppersmith
- small-roots
- crt
- lattice
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:44:38+08:00'
  notes: 已对照原文核对：state=1/0 过滤、12 模数 CRT 得 704 位高位、Coppersmith beta≈0.49 恢复 320 位低位与 PoC 一致。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

当 RSA 的素数 `p` 不是直接泄漏高位，而是以多条“小模数下的线性余数”形式给出时，先对 `state=1` 的记录逐条反解出 `p` 的高位分片，再用 CRT 合并成完整的 `p >> 320`（704 位），最后构造 `f(x) = upper·2^320 + x (mod n)` 用 Coppersmith `small_roots` 在 `beta≈0.49` 下恢复 320 位低位，即可分解 `n` 并解密。

## 原理

- **泄漏形式**：每条记录 `y ≡ a·upper_limb + b (mod m)`，其中 `m` 是约 2^60–2^61 的素数，`upper_limb = p >> 320`。`state=1` 有 12 条真实记录，`state=0` 是 3 条使用旧 `q` 的干扰记录，必须先过滤。
- **逐条反解**：`upper ≡ (y - b)·a^{-1} mod m`；每个 `m` 给出 `upper` 的一个余数。
- **CRT 合并**：12 个模数均为不同素数、两两互素；乘积约 731 位，大于 `upper` 的 704 位，因此 CRT 在模 `∏m` 下唯一确定 `upper = p >> 320`。
- **Coppersmith 小根**：已知 `p = upper·2^320 + low`，`0 ≤ low < 2^320`。构造模 `n` 的多项式 `f(x) = upper·2^320 + x`，`p | n` 且 `f(low) ≡ 0 (mod p)`；未知量只有 320 位，远小于 `p` 的一半（1024 位），满足一元 Coppersmith 条件。
- **参数选择**：`beta≈0.49`（`p ≈ n^0.5`，略低于 0.5 以避免边界问题），`X = 2^320`，`epsilon=0.02`；`small_roots` 返回小根后验证 `n % p == 0`。
- **为什么 decoy 必须剔除**：`state=0` 记录使用旧 `q >> 320`，与 `p` 的高位无关；混入 CRT 会得到错误的 `upper`，后续 Coppersmith 必然失败。
- **恢复后**：`q = n // p`，`φ=(p-1)(q-1)`，`d=e^{-1} mod φ`，解 `c^d mod n` 得明文。

## 触发条件

- RSA 使用两个大素数（本题各 1024 位，`n` 2048 位），`e=65537`。
- 泄漏 `p` 的高位分片：多条小模数线性同余式，模数两两互素且乘积位数大于高位分片位数。
- 未知低位位数小于 Coppersmith 可解上界（本题 320 位）。
- 存在干扰记录（state=0）需要用状态字段/一致性过滤。

## 利用步骤

1. 解析数据：`n, e, c, limb_bits=320, rows[]`；只保留 `state == 1` 的记录。
2. 对每条记录计算 `ai = inverse_mod(a, m)`，`x = (ai * ((y - b) % m)) % m`，收集 `(x, m)`。
3. 用 CRT 合并 12 个余数，得到 `upper = p >> 320`；检查 `upper.bit_length()` 是否为 704。
4. 在 Sage 中构造 `P.<x> = PolynomialRing(Zmod(n))`，`f = (upper * 2^320 + x).monic()`。
5. 调 `f.small_roots(X=2^320, beta=0.49, epsilon=0.02)`；取根 `low`，`p = upper*2^320 + low`。
6. 验证 `n % p == 0`；`q = n // p`，计算 `d` 并解密 `c`，把整数转字节得 flag。
7. 若 `small_roots` 无结果，依次调低 `beta`（0.49→0.48→…）、增大 `epsilon` 或检查 CRT 是否混入 decoy。

## PoC

```python
# sage
from sage.all import *

n = data["n"]; e = data["e"]; c = data["c"]
limb_bits = data["limb_bits"]          # 320
residues, moduli = [], []
for r in data["rows"]:
    if r["state"] != 1:                # 过滤 state=0 的旧 q 干扰
        continue
    m, a, b, y = r["m"], r["a"], r["b"], r["y"]
    ai = inverse_mod(a, m)
    residues.append(Integer((ai * ((y - b) % m)) % m))
    moduli.append(Integer(m))

M = prod(moduli)                       # ≈731 位
upper = Integer(CRT_list(residues, moduli))   # p >> 320，704 位

P.<x> = PolynomialRing(Zmod(n))
f = (upper * (2^limb_bits) + x).monic()
roots = f.small_roots(X=2^limb_bits, beta=0.49, epsilon=0.02)
assert roots
low = int(roots[0])
p = upper * (2^limb_bits) + low
assert n % p == 0
q = n // p
d = inverse_mod(e, (p - 1) * (q - 1))
m_int = power_mod(c, d, n)
print(int(m_int).to_bytes((int(m_int).bit_length() + 7) // 8, "big"))
```

原文用该脚本恢复 `p/q` 并解出 flag；未在本机复跑。

## 变体与关联

- **直接高位泄漏**：若已知 `p` 的连续高位，可跳过 CRT，直接构造同样的 Coppersmith 多项式；本卡的区别是高位由多条小模数余数拼出。
- **多位泄漏**：同时泄漏 `p`、`q` 的部分位，可用多元 Coppersmith 或已知位格攻击。
- **模数选择**：小模数乘积必须大于未知高位分片的位数；否则 CRT 结果不唯一。
- **decoy 变体**：用状态字段、时间戳、一致性（`n % p == 0`）或多次尝试过滤错误记录。
- **关联**：[[crypto-rsa-multiprime-partial-key-coppersmith]]（三素数高位泄漏 + beta 下调）；本卡是两素数 + CRT 聚合高位 + 320 位低位的组合。

## 检测与防御

- RSA 实现不要以任何形式泄漏素数高位/低位分片；对 API 返回的随机数、审计数据做最小化。
- 使用足够大的密钥与标准库；避免自制“部分信息”协议。
- 检测：同一 RSA 公钥伴随多条小模数线性同余式、状态字段异常、CRT 乘积可覆盖素数高位；密钥生成后做一致性自检。
