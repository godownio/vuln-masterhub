---
id: ctf-crypto-gf41-lagrange-substitution-inverse-hash-brute
title: GF(41) 拉格朗日插值还原替换表：已知前缀定多项式 + 反查候选 + SHA-256 约束穷举
type: scenario
domain: ctf
path: ctf/crypto
technique: gf41-lagrange-interpolation-substitution-hash-brute
tags:
- ctf
- crypto
- substitution
- lagrange-interpolation
- finite-field
- hash
- brute-force
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V231
  verified_at: '2026-11-07T09:49:19+08:00'
  notes: 已对照原文重构脚本与 flag 核对：GF(41) 拉格朗日插值、反向候选、约 3.54M 组合 SHA-256 穷举，输出 flkejiyliafg77c3c4f49335c711avg；原文代码缩进/空格错乱，卡内已整理。未复跑脚本。
url: /docs/ctf/crypto/ctf-crypto-gf41-lagrange-substitution-inverse-hash-brute/
draft: false
kb_aliases:
- 拉格朗日插值替换密码
- GF(41) 多项式替换
- why_not_substitution
- 已知明密文对恢复映射
- SHA-256 约束穷举
---

## 一句话结论

替换密码的字符集大小是素数 41（`!@#¥%` + `a-z` + `0-9`），已知 7 组明密文字符对即可在 GF(41) 上唯一确定一个次数 ≤6 的多项式 `f`（明文索引 → 密文索引）；用拉格朗日插值补全整张映射表，反向映射得到每个密文字符的全部候选明文，再对约 354 万种组合逐一做 SHA-256 与目标哈希比对，即可恢复 flag `flkejiyliafg77c3c4f49335c711avg`。

## 原理

- 字符集：`CHARSET = "!@#¥%" + ascii_lowercase + digits`，长度 41；41 是素数，索引 0..40 构成有限域 GF(41)，任意非零元素都有乘法逆元。
- 加密模型：替换表被设计成低次多项式 `c = f(p) mod 41`；已知 7 个明文前缀 `flkejiy` 及其对应密文，得到 7 个点 `(p_i, c_i)`，可插值出次数最多 6 的多项式 `f`（7 个点确定 7 个系数）。
- 拉格朗日插值：`f(x) = Σ y_i · Π_{j≠i} (x - x_j)/(x_i - x_j) mod 41`；分母是 GF(41) 中的非零差值，用 `pow(den, -1, 41)` 求逆，因此可在全域 `x=0..40` 上算出完整映射 `f_values`。
- 非一一映射：多项式 `f` 未必是双射，一个密文字符 y 可能对应多个明文索引 x；反向映射 `inv_map[y] = {x | f(x)=y}` 会给出候选列表，密文越长组合空间越大（本题约 3.54M）。
- 哈希约束：题目给出明文的 SHA-256，穷举所有候选组合并逐个计算哈希，唯一匹配的字符串即为明文；已知前缀的位置直接固定，进一步缩小空间。
- 为什么成立：多项式次数远小于字符集大小，7 个已知点足以恢复整张表；哈希提供了强校验，使多候选组合可以被离线过滤；组合数在可枚举范围内。

## 触发条件

- CTF crypto 题：替换/代换密码的字符集是素数大小（或可嵌入有限域），映射由低次多项式或有理函数定义。
- 已知明文前缀长度不少于多项式次数 + 1（本题 7 个点、次数 ≤6）。
- 题目提供明文的哈希/校验值（或明确的 flag 格式），可用于过滤候选组合。
- 密文长度与候选组合数在可枚举范围（本题约 3.54M，纯 Python `itertools.product` 可跑）。
- 需要正确识别字符集与索引顺序（多一个字符或少一个字符都会让插值失败）。

## 利用步骤

1. 确认字符集与索引：把 `CHARSET` 映射为 0..40，注意特殊字符与大小写。
2. 用已知前缀 `known_prefix` 与密文前 7 个字符构造点对 `(idx[明文], idx[密文])`。
3. 在 GF(41) 上做拉格朗日插值，计算 `f(0..40)` 得到完整映射表。
4. 建立反向映射 `y -> [x...]`；对密文每个位置列出候选明文字符，已知前缀位置固定。
5. 用 `itertools.product` 枚举所有组合，计算 SHA-256 与目标哈希比对，命中即输出 flag。
6. 若组合过多，可改用 meet-in-the-middle、z3 约束或按 flag 格式分段校验；若函数是双射，反向映射唯一，可直接解码。

## PoC

原文脚本（已整理缩进与空格）：

```python
from string import ascii_lowercase, digits
from itertools import product
import hashlib

CHARSET = "!@#¥%" + ascii_lowercase + digits
MOD = len(CHARSET)  # 41
enc = "quw7f59u51q¥##w¥w6q6s¥¥#w#661d¥"
known_prefix = "flkejiy"
target_hash = "7d41757168a2199b32cb1744de130fdebda25271116bc64eccf4e397770d73c2"

idx = {c: i for i, c in enumerate(CHARSET)}
points = [(idx[known_prefix[i]], idx[enc[i]]) for i in range(len(known_prefix))]

def modinv(a, m=MOD):
    return pow(a, -1, m)

def lagrange_eval(x, points, mod=MOD):
    total = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (x - xj)) % mod
            den = (den * (xi - xj)) % mod
        total = (total + yi * num * modinv(den, mod)) % mod
    return total

f_values = [lagrange_eval(x, points) for x in range(MOD)]

inv_map = {}
for x, y in enumerate(f_values):
    inv_map.setdefault(y, []).append(x)

candidates_list = []
for i, ch in enumerate(enc):
    chars = [CHARSET[x] for x in inv_map.get(idx[ch], [])]
    if i < len(known_prefix):
        chars = [known_prefix[i]]
    candidates_list.append(chars)

for combo in product(*candidates_list):
    s = "".join(combo)
    if hashlib.sha256(s.encode()).hexdigest() == target_hash:
        print("Flag:", s)
        break
```

```text
输出：flkejiyliafg77c3c4f49335c711avg
```

## 变体与关联

- 变体（已知点数量）：点数 = 次数 + 1；若只知道 6 个点则无法唯一确定，需要额外约束或枚举系数。
- 变体（映射类型）：若映射是有理函数 `f(x)=num(x)/den(x)`，需用 Berlekamp-Welch 或线性化方法；若映射是随机表，则退化为普通替换密码，需要频率分析/模拟退火。
- 变体（求解器）：组合空间过大时可用 z3 建模每个位置的候选约束 + 哈希前缀匹配，或 meet-in-the-middle 拆分密文。
- 关联：[[ctf-crypto-berlekamp-welch-rational-function-interpolation]]（有理函数插值恢复分子分母）、[[ctf-crypto-multivariate-elimination-univariate-polynomial]]（多元消元到单变量多项式）、[[ctf-crypto-blackbox-chosen-input-mapping]]（黑盒映射恢复）。
- 边界：字符集/索引判断错误、已知前缀与密文对不匹配、哈希目标不是整串明文时脚本找不到解；多项式次数高于已知点数时不唯一。

## 检测与防御

- 这是 CTF 密码题解法，不是真实系统漏洞；对密码设计者的启示是：不要用低次多项式/可插值的代换表作为加密，已知少量明密文对会泄露整张表。
- 使用标准带密钥的原语（AES/ChaCha20 等）和随机 nonce；不要把明文哈希作为可离线校验的 oracle 暴露给攻击者。
- 若必须做字符集替换，使用密钥化的伪随机置换（PRP）并隐藏映射结构；限制攻击者获得已知明密文对的数量。
