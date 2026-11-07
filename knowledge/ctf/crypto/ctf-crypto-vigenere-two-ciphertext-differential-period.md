---
id: ctf-crypto-vigenere-two-ciphertext-differential-period
title: 两次维吉尼亚加密同一明文：差分周期恢复密钥流并解 flag
type: scenario
domain: ctf
path: ctf/crypto
technique: vigenere-two-ciphertext-differential
aliases:
- The Imitation Game
- 维吉尼亚差分
- 同明文两次加密
- 周期 41
- ask and it shall be given
tags:
- crypto
- vigenere
- differential
- known-plaintext
- period
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:08:28+08:00'
  notes: 已对照原文核对：两段同明文差分周期 41、twhsnz/brassg 反推 askand/indask、密钥短语 askanditshallbegivenyouseekandyeshallfind、flag 两块相位 rot0/rot38、正文相位 rot15/rot12 与原文一致。未验证点：PoC 未本机复跑；CTF 题无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

两段密文的单词数、标点、换行结构完全一致，说明是同一明文被两次维吉尼亚加密；去掉非字母后逐字符做 `Δ=(c2-c1) mod 26`，差分严格以 41 为周期，结合已知 `texsaw` 前缀恢复密钥短语 `askanditshallbegivenyouseekandyeshallfind` 的不同循环位移，即可解出两段 flag。

## 原理

- **维吉尼亚**：`c_i = (p_i + k_i) mod 26`。同一明文用两套密钥流加密时，`c2_i - c1_i = k2_i - k1_i mod 26`，明文被消掉，只剩两套密钥流的差。
- **周期检测**：若密钥流周期为 `p`，差分序列也以 `p` 为周期。本题对两段正文去空格/标点后做差分，发现严格按 41 个字母循环，说明是周期多表替换且密钥长度 41。
- **已知前缀恢复密钥片段**：flag 格式为 `texsaw{...}`，两串 flag 密文前缀 `twhsnz` / `brassg` 与明文 `texsaw` 逐位相减，得到 `askand` / `indask`。这两个片段拼起来指向一句 41 字母的英文短语：`askanditshallbegivenyouseekandyeshallfind`（“Ask and it shall be given you; seek and ye shall find”）。
- **相位**：不同密文块的起始位置不同，密钥流要循环位移。flag 两块分别用 `rot(key,0)` 和 `rot(key,38)`；正文两块用 `rot(key,15)` 和 `rot(key,12)`（可枚举 41 个相位找可读英文）。
- **结果**：flag 解密为 `texsaw{luojmfsgmkqltenaemdqlxgtyrfdlzxdmqmxysvdettsxpatcq}`；正文是可读英文。

## 触发条件

- 有两段密文，长度/词数/标点/换行结构高度一致，疑似同一明文。
- 加密是周期性多表替换（维吉尼亚/博福特/格朗斯费尔德等）。
- 已知明文前缀或格式（如 `flag{`、`texsaw{`）。
- 密钥流长度可通过差分周期、Kasiski 或重合指数确定。

## 利用步骤

1. 把两段密文去掉非字母、转小写，确认长度一致。
2. 逐字符算 `Δ=(c2-c1) mod 26`，找最小周期 `p`（本题 41）。
3. 用已知明文前缀反推密钥片段；搜索/联想出完整密钥短语。
4. 对每个密文块枚举密钥流的 41 个循环位移，解出可读文本。
5. 用 flag 格式和英文语义验证；必要时对多段分别求相位。

## PoC

```python
import string
ALPHA = string.ascii_lowercase

flag_ct1 = "twhsnz{tngqmqdhqqygxrloyehuvxtwwvxklkiiudpxqcvqhbmkepledu}"
flag_ct2 = "brassg{lhrrfxzgxvrpzmierkrkdbkdyeibpredxbrflvvvotgvfisacb}"

def only_letters(s):
    return ''.join(ch for ch in s.lower() if ch in ALPHA)

def rot(s, n):
    return s[n:] + s[:n]

def vig_dec(text, key):
    out, j = [], 0
    for ch in text.lower():
        if ch in ALPHA:
            out.append(ALPHA[(ALPHA.index(ch) - ALPHA.index(key[j % len(key)])) % 26])
            j += 1
        else:
            out.append(ch)
    return ''.join(out)

base = "askanditshallbegivenyouseekandyeshallfind"
assert len(base) == 41
print(vig_dec(flag_ct1, rot(base, 0)))
print(vig_dec(flag_ct2, rot(base, 38)))
```

差分周期检测（正文两段）：

```python
def diff_period(a, b):
    ds = [(ALPHA.index(y) - ALPHA.index(x)) % 26 for x, y in zip(a, b)]
    for p in range(1, len(ds) + 1):
        if all(ds[i] == ds[i % p] for i in range(len(ds))):
            return p

# period = 41
```

## 变体与关联

- **同明文变体**：两段正文是同一明文的不同语言/不同密钥/不同相位；差分周期就是密钥长度。
- **密码变体**：维吉尼亚、博福特（`k-p`）、格朗斯费尔德（数字密钥）、自动密钥；差分公式不同但思路相同。
- **密钥恢复变体**：已知前缀、Kasiski、重合指数、字典短语；密钥可能是名言/歌词。
- **关联卡片**：[[ctf-crypto-vigenere-caesar-digit-letter-branch-counter-scope]]（维吉尼亚+凯撒复合）、[[ctf-crypto-aes-gcm-nonce-reuse-ghash-subkey-root]]（复用/差分思想）、[[crypto-classical-hill-cipher-3x3-matrix-inverse-mod26]]（古典多表/矩阵还原）。
- **边界**：若两段不是同一明文、密钥非周期、或差分周期不唯一，需要更多密文/已知明文；相位枚举要结合语言模型。

## 检测与防御

- **防御**：不要用同一明文配相关密钥重复加密；使用带随机 nonce/IV 的认证加密（AES-GCM/ChaCha20-Poly1305）。
- **检测信号**：两段密文结构完全一致；差分序列呈短周期；同一密钥流被不同相位复用。
- **CTF 技巧**：先做差分找周期，再用已知前缀锁定密钥片段，最后枚举相位。
