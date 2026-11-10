---
id: crypto-rsa-tiny-modulus-128bit-direct-factorization
title: RSA 模数只有约 128 位：直接用 factordb/sympy 分解 n 求 d，textbook 解密恢复口令（常见于流量包里泄露的 n/e/c）
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-tiny-modulus-direct-factorization
aliases:
- 小 n 直接分解
- 128 位 RSA
- n 144866671565187653968436368127956889323
- 流量包里的公钥参数
- factor(n) 重建私钥
tags:
- crypto
- rsa
- tiny-modulus
- factorization
- textbook-rsa
- ctf
- pcap
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:52:05+08:00'
  notes: 已对照原文核对：n=144866671565187653968436368127956889323（约 2^127）、e=65537、c=71296054321509316776624970111608994994 与原文一致，n 位数不足可分解、d=inverse(e,phi)、pow(c,d,n) 还原 8 位口令 99004462 的结论与原文一致；原文用 Sage factor(n)，卡内 sympy/factordb 为等价实现。本次核对未读取图片，仅依据正文；未验证点：未实际跑分解验证 p、q。
---

## 一句话结论

当泄露的 `n` 只有 100～160 位（十进制 30～50 位数字，约等于 2^128），它连现代 RSA 的下限都不是：`sympy.factorint`、`factordb` 或 Sage 的 `factor(n)` 都能在秒级分解，得到 `p`、`q` 后 `d = inverse(e, (p-1)(q-1))`，`m = pow(c, d, n)` 即还原明文；不需要任何格、广播或填充攻击。

## 原理

- RSA 安全性完全依赖"大整数分解困难"。128 位模数等价于 64 位素数因子，通用数域筛/椭圆曲线法在普通机器上是毫秒级，甚至试除到 `10^6` 就能命中不少题目。
- 密钥生成时必须保证 `n = p*q` 且 `p`、`q` 为强素数；题目若用 `random` 生成小素数、或从截断的随机字节拼出 `n`，就会退化为"n 小 → 可分解 → 私钥公开"。
- `e = 65537` 与 `n` 的位数无关：`d` 只要 `e*d ≡ 1 mod φ(n)` 即可，分解完成私钥就重建完毕。
- 明文是数字/短字符串时直接 `long_to_bytes(pow(c,d,n))`；若明文被当整数处理（例如口令 `99004462`），还要按题目约定做前导零补齐。
- 这类参数常见于 pcap 里被捕捉的握手/挑战数据：只要抓到 `n`、`e`、`c` 三件套，即可离线解。

## 触发条件

- 已知 `n`、`e`、`c`（可从流量包、配置文件、源码、接口响应获得）。
- `n` 位数明显不足（经验阈值：< 512 位基本都可疑，< 256 位几乎必可分解）。
- `n` 能被常见工具快速分解（factordb 命中、sympy 秒级返回）。

## 利用步骤

1. 从 pcap/报文里提取三个参数（如 `Protocol: RSA / n:... / e:... / Ciphertext:...`）。
2. 先查 `factordb.com` 是否有该 `n` 的分解（最快）。
3. 没有就本地分解：`sympy.factorint(n)` 或 Sage 的 `factor(n)`；小指数场景也可先试 `gmpy2.iroot`（完全平方/完全立方）。
4. `φ = (p-1)*(q-1)`，`d = pow(e, -1, φ)`（Python 3.8+）或 `inverse_mod(e, φ)`。
5. `m = pow(c, d, n)` → `long_to_bytes(m)`；若是数字口令，直接转十进制字符串。
6. 得到的口令/明文拿去解开下一层（本例是给门锁输入的 8 位解锁码）。

## PoC

```python
from sympy import factorint
from Crypto.Util.number import long_to_bytes

n = 144866671565187653968436368127956889323
e = 65537
c = 71296054321509316776624970111608994994

factors = factorint(n)              # {p: 1, q: 1}
p, q = list(factors)
d = pow(e, -1, (p - 1) * (q - 1))
m = pow(c, d, n)
print(m, long_to_bytes(m))
```

```python
# Sage 等价写法
# n = 144866671565187653968436368127956889323
# factors = factor(n); p, q = factors[0][0], factors[1][0]
# d = inverse_mod(65537, (p-1)*(q-1)); print(power_mod(c, d, n))
```

## 变体与关联

- `n` 是素数（不是两素数乘积）：`φ = n-1`，直接求逆。
- `n` 是三个及以上素数乘积（多素数 RSA）：`φ = ∏(p_i - 1)`，分解后同法。
- `n` 为完全平方（`n = p^2`）：`isqrt` 直接得 `p`。
- `n` 共享素因子（多组 `n` 一起出现）：批量 `gcd` 即可，无需分解。
- 位数够大时这些都不成立，才需要 Wiener/Boneh-Durfee/Coppersmith 等结构化攻击。

## 检测与防御

- 检测：证书/公钥位数低于组织基线（如 < 2048 位）；配置里出现硬编码 `n`；CTF 之外表现为"老旧或自研加密组件"。
- 防御：RSA 至少 2048 位，密钥由密码学安全随机源生成并校验 `p`、`q` 为强素数；使用 OAEP/PKCS#1 v1.5 填充而非 textbook RSA；定期用扫描器检查密钥位数与共享因子。
