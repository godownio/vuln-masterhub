---
id: crypto-implementation-small-lwe-secret-bruteforce-aes-key
title: 小参数 LWE 暴力枚举：n=6、s∈{0..3}、噪声±1 直接搜 secret 并派生 AES key
type: scenario
domain: crypto
path: crypto/implementation
technique: small-lwe-secret-bruteforce-aes-key
tags:
- lwe
- lattice
- brute-force
- aes-cbc
- small-parameters
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:45:56+08:00'
  notes: 已对照 lattice_oracle 原文与图片核对：n=6、q=97、s∈{0..3}、e∈{-1,0,1}、4^6 枚举、SHA256(str(secret))[:16] 派生 AES-CBC key，输出 secret=[0,0,2,1,1,1] 与 flag 均一致；PoC 未本机执行
url: /docs/crypto/implementation/crypto-implementation-small-lwe-secret-bruteforce-aes-key/
draft: false
kb_aliases:
- lattice_oracle
- 小参数 LWE
- LWE 暴力枚举
- secret 4^6 爆破
- 噪声 ±1
- AES key 派生
---

## 一句话结论

当 LWE 参数极小（`n=6`、`q=97`、`s_i∈{0,1,2,3}`、噪声 `e_i∈{-1,0,1}`）时，不需要格约减：直接枚举 `4^6=4096` 个 secret，对 30 组样本检查 `(a_i·s - b_i) mod q` 的居中表示是否都在 `{-1,0,1}`，唯一命中的 secret 即解；再把 `SHA256(str(secret))[:16]` 作为 AES-CBC key 解密即可。

## 原理

- LWE 样本：`b_i = <a_i, s> + e_i mod q`，`a_i` 公开、`s` 为 secret、`e_i` 为小噪声。
- 一般 LWE 需要格约减（LLL/BKZ/CVP）；但当 secret 空间很小（每个分量只有 4 种取值，总空间 4096）时，穷举比格攻击更简单。
- 对每个候选 `s`，计算 `diff_i = centered_mod(<a_i,s> - b_i, q)`，其中 `centered_mod` 把 `[0,q)` 映射到 `(-q/2, q/2]`；若所有 `diff_i ∈ {-1,0,1}`，候选极可能是真实 secret。
- 30 组样本提供足够约束，随机候选全部命中的概率极低；因此第一个满足的候选通常唯一。
- 题目用 `SHA256(str(solution).encode()).digest()[:16]` 作为 AES-128-CBC key，`iv`/`enc` 在 `data.txt` 中；解密后去 PKCS#7 padding 即 flag。
- 这个场景的教训是：LWE 安全性依赖参数（n、q、噪声分布、secret 空间）；参数过小会退化为暴力搜索。

## 触发条件

- 题目给出多组 `(a_i,b_i)`、模数 `q`、维度 `n`，且 secret 分量取值空间很小（如 `{0..3}`）。
- 噪声范围很小（如 `{-1,0,1}`），可用居中模差验证候选。
- secret 总空间 `k^n` 在可枚举范围内（案例 4096）。
- 有 AES-CBC 密文/iv，key 由 secret 的字符串形式派生。

## 利用步骤

1. 从 `data.txt` 读取 `n,q,A,b,iv,enc`。
2. 枚举 `itertools.product(range(4), repeat=n)` 的所有候选 secret。
3. 对每个候选，计算每组样本的 `diff = centered_mod(sum(a*s)-b, q)`；若任一 `diff` 不在 `{-1,0,1}` 则淘汰。
4. 第一个全部通过的候选即 secret；记录 `errors` 验证噪声范围。
5. 计算 `key = sha256(str(solution).encode()).digest()[:16]`。
6. 用 `AES.new(key, AES.MODE_CBC, iv).decrypt(enc)` 解密，去 PKCS#7 padding，输出 flag。

## PoC

```python
import hashlib, itertools, json
from pathlib import Path
from Crypto.Cipher import AES

def centered_mod(value, q):
    value %= q
    return value - q if value > q // 2 else value

def unpad(data):
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad]

data = json.loads(Path("data.txt").read_text())
n, q, A, b = data["n"], data["q"], data["A"], data["b"]
iv, enc = bytes.fromhex(data["iv"]), bytes.fromhex(data["enc"])

solution = None
for s in itertools.product(range(4), repeat=n):
    errors = []
    for row, target in zip(A, b):
        diff = centered_mod(sum(x * y for x, y in zip(row, s)) - target, q)
        if diff not in (-1, 0, 1):
            break
        errors.append(diff)
    else:
        solution = list(s)
        print("secret =", solution, "errors =", errors)
        break

assert solution is not None
key = hashlib.sha256(str(solution).encode()).digest()[:16]
print(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(enc)).decode())
```

案例输出：`secret = [0, 0, 2, 1, 1, 1]`，flag 为 `DASCTF{LWE_l4tt1c3_r3duct10n_i5_p0w3rful!}`。

## 变体与关联

- 变体：secret 空间稍大时改用 meet-in-the-middle、z3 约束求解或格约减（LLL/BKZ/CVP）。
- 变体：噪声范围更大时，候选验证阈值放宽或改用最大似然/最小二乘。
- 变体：key 派生可能是 `SHA256(secret bytes)`、`str(list)`、JSON 序列化等；按题目代码复现。
- 关联：[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（LLL/Kannan embedding 解 LWE）、[[crypto-implementation-mldsa-nonce-leak-least-squares-key-recovery]]（最小二乘）、[[ctf-crypto-z3-short-input-128bit-state-constraint]]（Z3 约束求解）。

## 检测与防御

- 防御：使用标准 LWE 参数（足够大的 n、q、噪声分布），不要用可枚举的小 secret 空间。
- 防御：密钥派生使用 CSPRNG/标准 KDF，不要用低熵 secret 的字符串哈希作为 AES key。
- 检测：代码中出现 `random.randint(0,3)` 生成 secret、`q=97` 等小参数、`itertools.product(range(4))` 枚举。
- 响应：发现参数过小后更换密钥/参数，审计历史密文是否可被暴力恢复。
