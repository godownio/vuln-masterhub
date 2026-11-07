---
id: crypto-rsa-e3-known-prefix-suffix-coppersmith
title: RSA e=3 已知前后缀：中间 32 字节未知的 Coppersmith 小根恢复
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-e3-known-prefix-suffix-coppersmith
aliases:
- Patient Zero
- e=3
- 已知前缀后缀
- 中间未知
- Coppersmith 小根
- stereotyped message
tags:
- crypto
- rsa
- e3
- coppersmith
- small-roots
- known-prefix
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:23:00+08:00'
  notes: 已对照原文核对：n/e=3/c/flag_length=37、prefix=SDGCTF_SECURE_MSG_V1::、suffix=::END、flag=SDG{+32 字节+}、m0 与 shift=256^len(suffix)、f(x)=(m0+x*shift)^3-c mod n、x 256 bit < n^(1/3)≈341 bit、Sage small_roots(beta=1)、flag SDG{b5d5e5c44e80ab9bc7343c103dee50c9} 均一致。未验证点：PoC 未本机用 Sage 复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

textbook RSA `e=3`，明文 `prefix + flag + suffix`，flag 37 字节且 `SDG{...}`；把中间 32 字节设为 x，构造 `(m0 + x*256^len(suffix))^3 - c ≡ 0 mod n`，x 仅 256 bit < n^(1/3)，Coppersmith 小根恢复。

## 原理

- **确定性拼接不是填充**：`m = b"SDGCTF_SECURE_MSG_V1::" + flag + b"::END"`，没有 OAEP 随机性；e=3 时 `c = m^3 mod n`。
- **仿射结构**：已知前后缀，把未知中间 32 字节记为 x；`m = m0 + x * 256^len(suffix)`，其中 `m0` 是未知位置填 0 后的整数。
- **小根条件**：x 是 256 bit；n 约 1024 bit，`n^(1/3) ≈ 341 bit`，x < n^(1/3)，满足 Coppersmith 一元小根条件（`beta=1`）。
- **求解**：在 `Zmod(n)` 上构造 `f(x) = (m0 + x*shift)^3 - c`，`small_roots(X=2^256)` 得到 x，转 32 字节拼回 flag。

## 触发条件

- RSA 使用小指数（e=3/5/17）且无随机填充。
- 明文有已知前缀/后缀/格式，未知中间足够短。
- 模数 n 远大于未知量（未知 bit < n^(1/e)）。
- 已知密文 c 与 n/e。

## 利用步骤

1. 从 `encrypt.py`/`public.txt` 读 n、e、c、flag 长度与格式。
2. 确定已知前后缀：`prefix = b"...SDG{"`、`suffix = b"}::END"`；未知长度 32。
3. `m0 = int.from_bytes(prefix + b"\x00"*32 + suffix, "big")`；`shift = 256**len(suffix)`。
4. Sage：`PR.<x> = PolynomialRing(Zmod(n)); f = (m0 + x*shift)^e - c`；`roots = f.monic().small_roots(X=2^(8*32), beta=1)`。
5. `x_val.to_bytes(32,"big")` 拼 `SDG{...}`；正向加密验证等于 c。

## PoC

```python
from sage.all import *

n = 108060031931266353758801330782473639320039225201311917178449705019176660696244872351271382486864507377607807538618062847665115562029186118435965272613853246476229261400861607263122402792644231190189479726984543802757846539830277258662001776505200445021146928156972061161319057790512542181820218329738735817807
e, c = 3, 100008878800318283632201438905641901786626112629628674497571793527658945303252408192518444765332808863922302554365942020285211201115839756042595666555111768855173496738344017257243733743578327510467420579901928469612017347331628546572717592447637046256354504562975982161650217253359159063440525548096128374926

prefix, suffix, unknown_len = b"SDGCTF_SECURE_MSG_V1::SDG{", b"}::END", 32
m0 = int.from_bytes(prefix + b"\x00" * unknown_len + suffix, "big")
shift = 256 ** len(suffix)

PR.<x> = PolynomialRing(Zmod(n))
f = (m0 + x * shift) ** e - c
roots = f.monic().small_roots(X=2 ** (8 * unknown_len), beta=1)
mid = int(roots[0]).to_bytes(unknown_len, "big")
print((b"SDG{" + mid + b"}").decode())
```

## 变体与关联

- **指数变体**：e=5/17 时未知量需更短；可用多段已知明文/格。
- **位置变体**：未知在开头/中间/结尾；多段未知可拆成多变量 Coppersmith 或逐段恢复。
- **填充变体**：若使用 OAEP/PKCS#1 v1.5，确定性小根不成立；需要填充预言机等。
- **关联卡片**：[[crypto-rsa-e3-small-plaintext-integer-cube-root]]（无模约减立方根）、[[crypto-rsa-partial-plaintext-high-bits-coppersmith]]（高位泄露）、[[crypto-rsa-affine-broadcast-crt-coppersmith]]（仿射广播）。
- **边界**：若未知中间超过 `n^(1/e)`，small_roots 失败；若明文被随机填充，需换攻击面。

## 检测与防御

- **CTF/验证**：恢复的 x 应使 `pow(m,e,n)==c`；flag 应符合格式与长度。
- **防御**：使用 OAEP 等随机化填充；不要用 textbook RSA；密钥长度足够；不要把 flag 直接拼在固定前缀后加密。
- **检测信号**：公钥 e 很小（3/5/17）；密文对应固定前缀协议；明文长度/格式泄露。
