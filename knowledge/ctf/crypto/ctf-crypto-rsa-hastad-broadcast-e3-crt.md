---
id: ctf-crypto-rsa-hastad-broadcast-e3-crt
title: RSA 小指数广播攻击：三组 e=3 同明文 CRT 合成后开立方
type: scenario
domain: ctf
path: ctf/crypto
technique: rsa-hastad-broadcast-e3
aliases:
- Håstad 广播攻击
- Hastad broadcast
- 小指数广播
- e=3 广播
- CRT 开立方
- 低指数 RSA
tags:
- ctf
- crypto
- rsa
- hastad
- broadcast
- crt
- low-exponent
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:44:48+08:00'
  notes: 已对照原文核对；三组 e=3 合成 1315 位、开立方精确，与共享素因子路径交叉验证一致
---

## 一句话结论

同一明文用相同的小公钥指数 `e=3`、不同且两两互素的模数分别加密时，把三组密文用 CRT 合成到 `m^3 mod n1n2n3`；若 `m^3 < n1n2n3`，合成值就是精确的 `m^3`，直接开立方即可恢复明文，无需分解任何模数。

## 原理

- **广播场景**：同一消息 `m` 用三个不同模数 `n1,n2,n3`、同一 `e=3` 加密，得到 `c_i = m^3 mod n_i`。
- **CRT 合成**：三组同余式可唯一确定 `M = m^3 mod N`，`N = n1*n2*n3`。
- **明文足够短**：若 `m^3 < N`（示例三元组合成 1315 位，`m^3` 未超过），则 `M = m^3` 是精确整数，不存在模回绕。
- **开立方即明文**：`gmpy2.iroot(M, 3)` 若返回 `exact=True`，根就是 `m`；若不精确，说明 `m^3 >= N`，需要 Coppersmith 等更复杂方法。
- **为什么成立**：RSA 的安全性依赖模数分解，但广播场景下攻击者不需要分解；CRT 把三个同余式合并，指数小使明文幂次没有溢出模数。

## 触发条件

- 同一明文用相同小指数（常见 `e=3`）加密多次。
- 各模数两两互素（gcd 为 1），且数量满足 `k >= e`（示例 3 组）。
- 明文长度满足 `m^e < ∏ n_i`（无填充或填充较短）。
- 攻击者拿到所有密文与模数。

## 利用步骤

1. 收集 `e=3` 的多组 `(n_i, c_i)`，确认明文相同（题面提示/相同前缀/相同长度）。
2. 验证模数两两互素；若存在共享因子，先走共享素因子路径。
3. 用 CRT 合并 `c_i` 得到 `M mod N`，其中 `N=∏n_i`。
4. 对 `M` 开 `e` 次整数根；`exact=True` 则得到明文，否则考虑 Coppersmith/填充方案。
5. 将根转字节，检查 flag 格式；用 `pow(m,e,n_i)==c_i` 对每组回环验证。
6. 与同题其他路径（如共享素因子）交叉比对，确认结果一致。

## PoC

```python
from sympy.ntheory.modular import crt
import gmpy2

ns = [n1, n2, n3]
cs = [c1, c2, c3]
M, N = crt(ns, cs)
assert M < N

root, exact = gmpy2.iroot(M, 3)
assert exact
plain = root.to_bytes((root.bit_length() + 7) // 8, "big")
print(plain)

# 回环校验
for n, c in zip(ns, cs):
    assert pow(int(root), 3, n) == c
```

原文实测：三组合成模数 1315 位，开立方精确命中，明文与共享素因子路径完全一致，最终 `flag{Sh4r3d_Pr1m3_0v3r_0TA_26}`。

## 变体与关联

- **指数变体**：`e=3/5/17` 等小指数；组数至少为 `e`，更多组可提高 `∏n_i` 从而更容易满足无回绕。
- **填充变体**：PKCS#1 v1.5/OAEP 会引入随机填充，破坏“同明文”条件；若填充线性相关，可用 Coppersmith 相关消息攻击。
- **混合路径**：同题可同时存在共享素因子；两条路径互相验证。
- **关联卡片**：[[crypto-rsa-common-modulus]]（同一模数、不同指数）、[[ctf-crypto-rsa-shared-prime-batch-gcd]]（共享素因子分解）、[[crypto-rsa-fermat-close-prime-factorization]]（模数分解）。
- **边界**：`m^3 >= ∏n_i` 时 CRT 值发生回绕，简单开立方失败；模数不互素时 CRT 不适用；明文不同则不能广播。

## 检测与防御

- **CTF 验证**：`iroot` 必须 `exact=True`，并对每组密文回环校验；只得到“看起来像明文”的字节不足以确认。
- **工程防御**：RSA 公钥指数使用 65537；加密必须使用随机化填充（OAEP）；同一消息不要用同一小指数向多个接收方广播。
- **检测信号**：批量公钥指数为 3/5；同一明文/相同长度密文对应多个模数；模数乘积远大于明文幂次。
- **复盘**：看到“多个模数 + 小指数 + 同明文”先试 CRT 开根，再考虑分解类攻击。
