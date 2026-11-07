---
id: crypto-rsa-e3-small-plaintext-integer-cube-root
title: RSA e=3 明文过短：密文未模约减时直接整数立方根恢复
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-e3-small-plaintext-integer-cube-root
tags:
- crypto
- rsa
- low-exponent
- cube-root
- small-message
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:48:57+08:00'
  notes: 已对照原文「告别季」核对并复算：e=3、N 约 1536 bit，c 直接整数立方根精确，得 flag{women_yaozenyangshuochu_zaijianne}（39 字节，m^3≈936bit<N），与原文一致；卡片无填充、短明文条件与边界说明正确。未验证点：未持附件复跑；无版本/CVE；frontmatter 无 sources/source_url。
url: /docs/crypto/rsa/crypto-rsa-e3-small-plaintext-integer-cube-root/
draft: false
kb_aliases:
- RSA 小明文
- e=3 立方根
- 未模约减
- integer_nthroot
- 低指数攻击
---

## 一句话结论

RSA 使用 `e=3` 时，如果明文 `m` 很短、满足 `m^3 < n`，那么密文 `c = m^3 mod n` 实际上没有发生模约减，`c` 就是普通整数立方；对 `c` 求整数三次根即可恢复 `m`，不需要分解 `n` 或私钥。

## 原理

- **RSA 加密**：`c = m^e mod n`。当 `m^e < n` 时，`m^e` 本身小于模数，`mod n` 不改变值，所以 `c = m^e` 是精确的整数幂。
- **低指数**：`e=3` 时条件为 `m^3 < n`。本题 `n` 约 1536 bit，flag 只有几十字节（约 300 bit），`m^3` 约 900 bit，远小于 `n`，因此没有模约减。
- **整数根**：对 `c` 做 `integer_nthroot(c, 3)`，若余数为 0（`exact=True`），得到精确的 `m`；若有多个候选/填充，需要按明文格式（`flag{...}`）验证。
- **为什么成立**：这是“小明文/低指数”攻击的最简单形式；不需要 Coppersmith，也不需要知道 `p/q`。如果 `m^3 > n`，密文会回绕，整数根不再精确，需要 Coppersmith/广播/Håstad 等方法。
- **边界**：`m` 的长度必须满足 `m^3 < n`（约 `n^(1/3)`）；`e` 越大条件越严格；若使用了随机填充，`m` 变长/随机，攻击失效。

## 触发条件

- RSA 公钥指数 `e` 很小（常见 3），且明文很短/结构化（如短 flag）。
- 加密时没有填充，或填充后仍满足 `m^e < n`。
- 拿到 `n`、`e`、`c`；`c` 的整数 `e` 次根精确（余数为 0）。
- 明文格式可验证（`flag{...}`、固定前缀）。

## 利用步骤

1. 确认 `e=3`（或小指数）、`n` 的位长、`c` 的大小；估算 `c` 的立方根是否约等于明文长度。
2. 用 `sympy.integer_nthroot(c, 3)` 或 `gmpy2.iroot(c, 3)` 求整数根，检查 `exact`/余数。
3. 把根转大端字节，检查是否以 `flag{` 开头、以 `}` 结尾；若有多余填充，按格式截取。
4. 用 `pow(m, 3, n) == c` 回代验证；本题得到 `flag{women_yaozenyangshuochu_zaijianne}`。
5. 若根不精确，说明 `m^3 > n`，改用 Coppersmith 小根/广播攻击/相关消息攻击。

## PoC

```python
from sympy import integer_nthroot

c = 37200871830677789908396551249543062637188978192630580181459724500444997949046932604271895351388763870279778575053912860012758908346269536765620259753461261401130192826626734845716857635735893923996366934581919022064045623345585748996968570735079180805789002573008815409176075596901

m, exact = integer_nthroot(c, 3)
assert exact, "c is not a perfect cube"
plain = m.to_bytes((m.bit_length() + 7) // 8, "big")
print(plain.decode())     # flag{women_yaozenyangshuochu_zaijianne}
```

## 变体与关联

- **变体（m^e > n）**：用 Coppersmith 小根（已知部分明文/填充）、Håstad 广播（同一明文多组低指数）、相关消息攻击。
- **变体（e=3 + 多接收方）**：中国剩余定理合成 `m^3` 后再开立方；见广播攻击。
- **变体（填充）**：PKCS#1 v1.5 填充下 `m` 变长，需 Bleichenbacher 类攻击；OAEP 通常使小明文攻击失效。
- **关联卡片**：[[crypto-rsa-common-modulus]]（共模攻击）、[[crypto-rsa-multiprime-partial-key-coppersmith]]（Coppersmith 小根）、[[ctf-crypto-rsa-hastad-broadcast-e3-crt]]（Håstad 广播）。
- **边界**：`m^3<n` 是硬条件；`c` 不是完全立方时不能用；填充/随机化会让明文变长；`n` 太小可能被直接分解。

## 检测与防御

- **填充**：使用 OAEP（RSA-OAEP）或至少 PKCS#1 v1.5，避免无填充 RSA；随机填充使明文变长且不可预测。
- **指数/密钥**：`e=65537` 是常见安全选择；`e=3` 本身不是漏洞，但必须配合正确填充和足够长的明文。
- **检测**：CTF/审计中看到 `e=3`、短 flag、`c` 远小于 `n`，先试整数立方根；生产环境检查 RSA 实现是否使用无填充/短明文。
- **响应**：不要把短秘密直接作为 RSA 明文；密钥/消息长度遵循标准。
