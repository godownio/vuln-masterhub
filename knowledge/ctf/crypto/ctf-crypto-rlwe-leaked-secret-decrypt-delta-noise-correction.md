---
id: ctf-crypto-rlwe-leaked-secret-decrypt-delta-noise-correction
title: RLWE 挑战：泄露私钥 s 后用 c0+s·c1 解出 delta·m，模 delta 与负噪声修正恢复明文
type: scenario
domain: ctf
path: ctf/crypto
technique: rlwe-leaked-secret-delta-decrypt
aliases:
- RLWE 已知私钥解密
- Ring-LWE 解密
- c0 + s*c1
- delta=q//t
- 负噪声修正
- 格密码 CTF
tags:
- ctf
- crypto
- rlwe
- ring-lwe
- lattice
- decryption
- noise
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V511
  verified_at: '2026-11-11T04:57:14+08:00'
  notes: 已通读原文 13424 第三篇并自写整数多项式实现独立复算（未执行原文 exp）：n=128、q=2^60、t=2^32、delta=q//t=2^28、模 x^128+1，按 b=−a·s−e、c0=b·u+e1+delta·m、c1=a·u+e2 生成密文，final=c0+s·c1 后按 //delta 与余数>100000 加 1 修正，完整恢复原 hex 消息（flag{test_rlwe...} 验证通过）。核对中发现并修正卡片一处符号笔误：因 b=−as−e，噪声应为 −e·u+e1+s·e2（原写 e·u+…），已同步修改 knowledge 卡与 staging 草稿，量级结论不变。原文解密 exp 的 [:76]、阈值 100000、十六进制字符 ASCII 编码与卡一致。原文无图片。dedup 报告 new，候选（NTRU/LLL/LWE 格攻击、噪声泄露最小二乘等）均非同链。
---

## 一句话结论

题目实现的是标准 Ring-LWE 公钥加密（`R_q = Z_q[x]/(x^n+1)`，`q=2^60`、`t=2^32`、`delta=q//t`），并把私钥 `s` 一起打印出来；拿到 s 后计算 `c0 + s·c1 = delta·m + (e·u + e1 + s·e2)`，后面的噪声相对 delta 很小，对每个系数整除 delta（或四舍五入）即可恢复消息多项式，唯一要处理的是负噪声导致的向下取整误差（余数较大时商加 1）。

## 原理

- **参数与密钥**：`n=128`，模多项式 `x^n+1`，`q=2^60`，明文模 `t=2^32`，`delta=q//t=2^28`。私钥 `s` 的系数为 0/1；公钥 `b = −a·s − e`，其中 `a` 在 `Z_q` 上均匀随机，`e` 是均值 0、标准差 2 的小高斯噪声。
- **加密**：
  - 明文 `m` 是 flag 的十六进制字符串逐字符取 ASCII（0–9、a–f 的 ASCII 码），补 0 到长度 n，再模 t；
  - `c0 = b·u + e1 + delta·m`，`c1 = a·u + e2`，其中 `u` 的系数为 0/1，`e1/e2` 为小噪声。
- **解密（已知 s）**：
  - `c0 + s·c1 = (b·u + e1 + delta·m) + s·(a·u + e2)`；
  - 代入 `b = −a·s − e`，`−a·s·u + s·a·u` 抵消，得 `delta·m + (−e·u + e1 + s·e2)`；
  - 噪声项 `−e·u + e1 + s·e2`（符号不影响量级）的系数远小于 `delta=2^28`，因此对每个系数做 `//delta`（或除以 delta 后取最近的整数）就能恢复 `m` 的系数。
- **负噪声修正**：若噪声为负，`floor((delta·m + noise)/delta)` 会比真实 `m` 小 1。文章的做法是先取商 `temp = final // 2^28`、再取余 `temp1 = final % 2^28`，若 `temp1[i] > 100000` 则把 `temp[i]` 加 1（余数接近 delta 说明被向下取整吃掉了 1）。
- **编码还原**：`m` 的每个系数是十六进制字符的 ASCII 码；把恢复出的前 76 个系数转成字符拼成十六进制字符串，再 `int(hex_str, 16)` → `long_to_bytes` 得到 flag（前 76 个字符对应 flag 的十六进制长度，后续为补 0）。
- **为什么成立**：RLWE 的安全性依赖私钥 s 保密；题目把 s 与公钥/密文一起输出，等于直接给出解密陷门（decryption oracle）。噪声项虽在，但相对 delta 可忽略，舍入即可纠错。
- **边界**：若噪声参数过大或 delta 太小，舍入会出错（需要 Babai 最近平面/格约减）；本题参数下直接整除 + 余数修正即可。

## 触发条件

- 题目/实现基于 Ring-LWE（多项式环 `Z_q[x]/(x^n+1)`）提供公钥、密文，并泄露私钥 `s`（或等价解密陷门）。
- 已知 n、q、t、模多项式与密文多项式 `c0/c1`（以及可选的 `a/b/s`）。
- 明文按十六进制字符 ASCII 编码进多项式系数。

## 利用步骤

1. 识别 RLWE：看到 `poly_mul`/`poly_add`、`q=2^60`、`t=2^32`、`a/b/s`、`c0/c1` 与 `x^n+1` 模多项式，即可判定。
2. 用私钥计算 `final = c0 + s·c1 mod (q, x^n+1)`。
3. 对每个系数做 `q_i = final_i // delta`、`r_i = final_i % delta`；若 `r_i` 较大（接近 delta）则 `q_i += 1`。
4. 取前 `flag_hex_len`（题中 76）个系数，按 ASCII 码转字符拼成十六进制字符串，`int(s,16)` 后 `long_to_bytes`。
5. 验证 flag 格式；若出现乱码，检查噪声符号、delta 取整方式与字符长度。

## PoC

```python
import numpy as np
from Crypto.Util.number import long_to_bytes

n = 128
q = 2**60
t = 2**32
poly_mod = np.array([1] + [0]*(n-1) + [1])

def poly_mul(x, y, z, mod):
    from numpy.polynomial import polynomial as poly
    init = poly.polymul(x, y)
    res = poly.polydiv(init % z, mod)[1] % z
    return np.int64(np.round(res))

def poly_add(x, y, z, mod):
    from numpy.polynomial import polynomial as poly
    init = poly.polyadd(x, y)
    res = poly.polydiv(init % z, mod)[1] % z
    return np.int64(np.round(res))

final = poly_add(c0, poly_mul(s, c1, q, poly_mod), q, poly_mod)

delta = q // t
temp = (final // delta)[:76]
rem = (final % delta)[:76]
hex_str = ""
for i in range(len(temp)):
    hex_str += chr(temp[i] + 1 if rem[i] > 100000 else temp[i])
print(long_to_bytes(int(hex_str, 16)))
```

## 变体与关联

- **s 未泄露**：需要格攻击/LLL 恢复私钥或明文，见 `ctf-crypto-ntru-lattice-lll-private-key-recovery`、`ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe`、`crypto-implementation-small-lwe-secret-bruteforce-aes-key`。
- **编码变体**：明文可直接按位/字节编码到系数；也可能用 `q/2` 偏移编码（Kyber 风格），见 `ctf-crypto-cdf-comments-qhalf-bit-encoding-aes`。
- **噪声修正变体**：四舍五入、Babai 最近平面、中心化余数（把 `r_i > delta/2` 视为负）都可替代文章的经验阈值。
- **边界**：参数不够“LWE 安全”（q/t 太小、噪声太大）时舍入会失败；需要根据噪声分布选择纠错方式。

## 检测与防御

- **CTF/实现侧**：不要把私钥 `s`、随机种子或解密中间量打印到输出/日志；RLWE 的 s 一旦泄露即等同明文。
- **参数审计**：检查 q、t、delta 与噪声分布是否满足解密正确性；避免使用会暴露秘密的调试输出。
- **防御**：生产环境使用标准化 KEM/PKE（Kyber 等）并隔离密钥；调试构建中去掉密钥打印。
