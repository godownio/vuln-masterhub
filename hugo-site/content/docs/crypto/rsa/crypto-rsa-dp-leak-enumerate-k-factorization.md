---
id: crypto-rsa-dp-leak-enumerate-k-factorization
title: RSA dp 泄露：e·dp−1 为 p−1 的倍数，枚举小 k 分解 n 并恢复私钥解密
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-dp-leak-enumerate-k-factorization
tags:
- crypto
- rsa
- dp-leak
- partial-key
- factorization
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T06:30:57+08:00'
  notes: 已对照原文证书修复 flag3 核对：dp、n、e、c 与原文一致，e·dp-1 枚举 k 分解 n 的推导与 exp 一致；原文明示该段解出 flag3 片段。
url: /docs/crypto/rsa/crypto-rsa-dp-leak-enumerate-k-factorization/
draft: false
kb_aliases:
- dp 泄露
- e*dp-1 分解 n
- 部分私钥恢复
- 小因子枚举
- RSA 私钥恢复
- dp 侧信道
---

## 一句话结论

RSA 只泄露 `dp = d mod (p-1)` 时，由 `e·dp ≡ 1 (mod p-1)` 可知 `p-1` 整除 `e·dp-1`；枚举小因子 k 令 `p=(e·dp-1)/k+1` 并用 `n % p == 0` 验证，即可分解 n、恢复 q 与私钥 d，解密密文。

## 原理

- **dp 的定义**：`dp = d mod (p-1)`，即 `d = dp + k(p-1)` 对某个整数 k 成立。
- **关键同余**：RSA 中 `e·d ≡ 1 (mod φ(n))`，`φ(n)=(p-1)(q-1)`。因为 `p-1` 是 φ(n) 的因子，该同余在模 `p-1` 下也成立：`e·d ≡ 1 (mod p-1)`。代入 `d = dp + k(p-1)` 得 `e·dp ≡ 1 (mod p-1)`，即 `p-1 | (e·dp-1)`。
- **枚举 k**：写 `e·dp-1 = k·(p-1)`，则 `p = (e·dp-1)/k + 1`。k 通常与 e 同量级甚至更小（`k=(e·dp-1)/(p-1)`），遍历 `k=1..e` 即可覆盖绝大多数情况；对每个整除的 k 计算候选 p，用 `n % p == 0` 验证。
- **恢复私钥**：找到 p 后 `q=n//p`，`φ=(p-1)(q-1)`，`d=e^{-1} mod φ`，`m=pow(c,d,n)`；也可用 dp/dq/iqmp 做 CRT 解密。
- **为什么有效**：dp 泄露等于泄露了 p-1 的一个大倍数 `e·dp-1`，而 p 是 n 的因子；只需在小范围内试除 k，就把“分解大整数”降为“枚举小因子”。
- **补充**：若 k 范围不确定，可用 `gcd(pow(a, e·dp-1, n)-1, n)` 对随机 a 求因子（概率性），或扩大 k 枚举范围。

## 触发条件

- 题目/侧信道泄露 `dp`（或 `dq`），同时给出 n、e 与密文 c。
- k 较小（通常 < e），可在可接受范围内枚举。
- 标准 RSA，p、q 为素数，e 与 φ(n) 互素。
- 若泄露的是 dq，可对称地用 `e·dq-1` 分解出 q。

## 利用步骤

1. 收集 n、e、dp、c。
2. 计算 `edp1 = e*dp - 1`。
3. 对 k=1..e（必要时扩大）遍历：若 `edp1 % k == 0`，令 `p = edp1//k + 1`，检查 `n % p == 0`。
4. 命中后 `q = n//p`，`phi=(p-1)*(q-1)`，`d=invert(e,phi)`。
5. `m=pow(c,d,n)`，`long_to_bytes(m)` 得到明文；也可用 dp/dq/iqmp 的 CRT 解密。
6. 若枚举失败，尝试 gcd 方法或扩大 k 范围。

## PoC

```python
from Crypto.Util.number import long_to_bytes
import gmpy2

e = 65537
n = 161097000312435047639025857083798608426453770394810689419872061300529854423940452844900091705515387130272189159935215821125906831946941166430461267964034092194438035823677086083564924149614045494613496178826123777949284989729443312266399276493423985154752448654420778684877265358368899693320567387749119123981
dp = 0x00a1a5b680d1d6c14dba3752a2beb7b9758526eb187957da4663283bff00062a774c5d9eaf7d7b52a17594dcc975507e9ad55db9aa061a9158c93be8f3c8b3b655
c = 0xD9A37C6673533106C25E43B902533758A4460DB38F7AA62811E25663C5DE91F3719485EEA9276AE374FCD06050EED6400463208D6DD206E9B55E2F885C770B6EDFBE72F17C42EC2EBFD66F1271E1A6CAB9470D0AC9136577FA19D5C0EA401D218F8BCB67154F1F2D69867B82D12B91D28B4492D42C3F89301D7C90A4BB02833C

for k in range(1, e + 1):
    if (dp * e - 1) % k == 0:
        p = (dp * e - 1) // k + 1
        if n % p == 0:
            q = n // p
            phi = (p - 1) * (q - 1)
            d = gmpy2.invert(e, phi)
            print(long_to_bytes(pow(c, d, n)))
            break
```

原文运行得到 flag3（三 flag 拼接的一部分）。

## 变体与关联

- 泄露变体：dq 泄露（对称分解 q）、dp 与 dq 同时泄露、只泄露 dp 高位/低位（转 Coppersmith）。
- 枚举变体：k 范围 1..e、1..2^16、按 `e·dp-1` 的因子分解；k 很大时用 gcd 方法。
- CRT 变体：恢复 p、q 后用 dp/dq/iqmp 做 CRT 解密；或直接恢复 d。
- 关联卡片：[[crypto-rsa-dp-leak-composite-modulus-power-coppersmith]]（复合模数 P/Q 上的 dp 泄露 + Coppersmith）、[[crypto-rsa-d-leak-factor-n-reuse-modulus-new-e]]（d 泄露）、[[crypto-rsa-private-exponent-low-bits-partial-p]]（d 低位泄露）、[[crypto-rsa-partial-e-coppersmith-hgs-multi-key-small-d]]。
- 边界：若 dp 泄露但 k 超出生效范围、或 e 与 φ(n) 不互素，需改用其他方法；本卡针对标准 RSA。

## 检测与防御

- 不要在任何日志、报错、侧信道中泄露 dp/dq/d/φ(n) 等私钥组件；RSA 实现使用常数时间与盲化。
- 使用 CRT 时防止故障攻击与计时/功耗侧信道；对私钥运算做完整性校验。
- 密钥生成使用密码学安全随机素数；私钥文件加密存储、最小权限访问。
- 红队/CTF 侧：看到 dp 与 n 同时出现，优先尝试 `e·dp-1` 枚举与 gcd 分解。
