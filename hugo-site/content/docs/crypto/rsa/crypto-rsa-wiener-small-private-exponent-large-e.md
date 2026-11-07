---
id: crypto-rsa-wiener-small-private-exponent-large-e
title: RSA Wiener 攻击：公开指数 e 异常大、私钥 d 过小，连分数收敛恢复 d
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-wiener-continued-fraction-small-d
tags:
- rsa
- wiener
- continued-fraction
- small-d
- private-key-recovery
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:08:53+08:00'
  notes: 已对照原文 evil_bash 段核对：e 接近 1024 位、d=0xb6279f56fe93aacf95b7、连分数收敛与 ed-1=kφ 验证流程正确；PoC 未本机复跑；原文未标注组件版本。
url: /docs/crypto/rsa/crypto-rsa-wiener-small-private-exponent-large-e/
draft: false
kb_aliases:
- Wiener attack
- 维纳攻击
- 大 e 小 d
- 连分数恢复私钥
- RSA 小私钥指数
---

## 一句话结论

RSA 的公开指数 `e` 异常大（接近模数 `n`）而私钥指数 `d` 很小时，`e/n` 的连分数收敛中会出现 `k/d`；枚举收敛、用 `ed - 1 = k·φ(n)` 解出 `p+q` 并验证 `p·q = n`，即可恢复 `d`，解密所有用该公钥加密的数据。

## 原理

- RSA 中 `ed ≡ 1 (mod φ(n))`，即 `ed - 1 = k·φ(n)`，其中 `k < d`。当 `d` 很小时，`e/n` 与 `k/d` 非常接近，`k/d` 会出现在 `e/n` 的连分数收敛序列中（Wiener 定理：`d < (1/3)·n^(1/4)` 时必然出现）。
- 对每个收敛 `k/d`：
  - 检查 `(e·d - 1) % k == 0`，令 `φ = (e·d - 1) / k`；
  - 由 `φ = (p-1)(q-1) = n - (p+q) + 1` 得 `s = p+q = n - φ + 1`；
  - 解二次方程 `x² - s·x + n = 0`，判别式 `s² - 4n` 必须是完全平方；
  - 若 `p·q = n`，则 `d` 正确。
- 为什么 `e` 会异常大：当 `d` 很小时，由 `ed ≡ 1 mod φ` 得 `e ≈ k·φ/d`，`k` 与 `d` 同量级时 `e` 会接近 `n`；这与常见 `e=65537` 形成明显反差，是识别 Wiener 场景的强特征。
- 与 Boneh-Durfee 的区别：Wiener 适用于 `d < n^0.25/3` 左右；更大的小私钥需要格基约减（Boneh-Durfee，`d < n^0.292`）。

## 触发条件

- 已知 RSA 公钥 `(n, e)`，且 `e` 异常大（接近 `n` 的位数）或明显不符合常规取值。
- 私钥指数 `d` 满足 Wiener 界（约 `d < (1/3)n^(1/4)`）。
- 有使用该公钥加密的密文（或需要恢复私钥用于签名/解密）。
- 能进行大整数连分数/二次方程计算（Python 标准库即可）。

## 利用步骤

1. 从握手/配置/公钥文件中提取 `n`、`e`，观察 `e` 的位数；若 `e` 与 `n` 同量级，优先尝试 Wiener。
2. 计算 `e/n` 的连分数展开，生成收敛序列 `k/d`。
3. 对每个收敛：检查 `(e·d - 1) % k == 0`，求 `φ`、`s = n - φ + 1`，判断 `s² - 4n` 是否为完全平方。
4. 验证 `p·q == n`；成功则得到 `d`。
5. 用 `d` 对密文做 RSA 解密（注意分组/填充/块大小）；若密文按固定块变换（如 128→126 字节），按相同块大小逐块 `pow(c, d, n)` 并拼接。
6. 对解密结果做格式识别（Base64、压缩包、多层加密），继续后续还原。

## PoC

```python
import math

def continued_fraction(a, b):
    terms = []
    while b:
        q = a // b
        terms.append(q)
        a, b = b, a - q * b
    return terms

def convergents(terms):
    p0, p1, q0, q1 = 0, 1, 1, 0
    for t in terms:
        p0, p1 = p1, t * p1 + p0
        q0, q1 = q1, t * q1 + q0
        yield p1, q1

def wiener(n, e):
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = math.isqrt(disc)
        if r * r != disc:
            continue
        if (s + r) % 2:
            continue
        p, q = (s + r) // 2, (s - r) // 2
        if p * q == n:
            return d
    return None

# d = wiener(n, e)
# m = pow(c, d, n)
```

说明：PoC 为原文脚本的结构化精简，未在本机执行；原文从自定义协议的握手包中取 `n,e`，恢复 `d=0xb6279f56fe93aacf95b7` 后解密外传包。

## 变体与关联

- 变体（Boneh-Durfee）：`d < n^0.292` 但超出 Wiener 界时，用格基约减（LLL）求解；见关联卡。
- 变体（部分 d）：已知 `d` 的部分比特时用 Coppersmith/格方法补全。
- 变体（多密钥）：同一 `d` 用于多个模数、或共享素因子时，可结合 GCD/共模攻击。
- 关联：[[crypto-rsa-boneh-durfee-small-private-exponent]]（更大的小私钥）；[[crypto-rsa-partial-e-coppersmith-hgs-multi-key-small-d]]（部分 e/多密钥小 d）；[[crypto-rsa-shared-prime-batch-gcd]]（共享素因子）。
- 边界：`d` 超出 Wiener 界、`e` 正常、或密文使用 OAEP 等填充时，本方法不成立或需先处理填充。

## 检测与防御

- 检测：公钥中 `e` 异常大（接近 `n` 位数）、`e` 不是 3/65537 等常规值；密钥生成日志中出现小 `d`；同一公钥被大量用于加密敏感数据。
- 防御：使用标准密钥生成（`e=65537`，`d` 足够大）；遵循 FIPS/厂商推荐的密钥长度与随机源；不要自实现 RSA 参数生成。
- 加固：私钥使用 HSM/密钥管理服务保护；定期轮换；对异常公钥参数做上线前检查（`d` 大小、`e` 范围、`p/q` 差值）。
- 取证：从协议握手/配置中提取 `n,e`，先跑 Wiener/Boneh-Durfee 检查，再决定是否需要分解 `n`。
