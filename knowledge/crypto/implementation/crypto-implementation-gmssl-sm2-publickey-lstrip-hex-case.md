---
id: crypto-implementation-gmssl-sm2-publickey-lstrip-hex-case
title: Python gmssl SM2 公钥 lstrip("04") 前缀剥离错误与 hex 大小写导致的签名不匹配
type: scenario
domain: crypto
path: crypto/implementation
technique: gmssl-sm2-publickey-prefix-hex-pitfall
aliases:
- gmssl lstrip 04
- SM2 公钥前缀处理
- bytes.hex 大小写
- SM3 签名不匹配
- C1C2C3 模式
- SM2 KDF 输入
tags:
- crypto
- sm2
- sm3
- gmssl
- python
- implementation
- hex
- signature
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V66
  verified_at: '2026-11-05T12:19:27+08:00'
  notes: 已对照原文核对：lstrip('04') 按字符集合删除会导致 040AE4...→AE4C7...，正确应为 [2:]→0AE4C7...；X 以 7 开头时两者恰好一致；SM3 签名对 data/secretKey/shareKey 的 hex 大小写敏感；shareKey 作 SM2 明文是 UTF-8 字符串字节而非 hex 解码；C1C2C3/C1C3C2 需与客户端一致。原文称 Python bytes.hex() 默认大写与 Python 3 实际返回小写不符，卡内已注明并保留‘签名前统一大小写’结论。本卡为复现坑点而非目标漏洞，severity low 合理；PoC 未在本机执行。
---

## 一句话结论

用 Python gmssl 复现客户端 SM2 加密时，`public_key.lstrip("04")` 会把 "04" 当成字符集合而非前缀剥离，公钥 X 坐标以 0/4 开头时会多剥字符导致曲线点错误；同时 SM3 签名串对 hex 大小写敏感，客户端小写 hex 与复现端输出不一致会直接导致验签失败——这类跨语言实现差异是国密协议复现最常见的坑。

## 原理

- 未压缩 SM2 公钥格式为 `04 || X(32B) || Y(32B)`，共 65 字节、130 hex 字符。正确去除前缀应取 `public_key[2:]`。
- 但 gmssl 的 `CryptSM2.__init__` 使用 `public_key.lstrip("04")`。Python 的 `str.lstrip(chars)` 语义是"删除开头所有属于 chars 集合的字符"，集合为 `{'0','4'}`：
  - `"040AE4C7...".lstrip("04")` → `"AE4C7..."`，X 坐标开头的 `0` 也被剥掉，长度变成 127 hex，曲线点解析错误；
  - 正确：`"040AE4C7..."[2:]` → `"0AE4C7..."`。
- 当公钥 X 坐标以 `7` 开头时，`lstrip("04")` 与 `[2:]` 结果恰好一致，掩盖了该 bug；换一把公钥就可能突然失败，因此很难排查。
- SM3 签名对输入字符串逐字节敏感。签名串形如 `SM3("data=<data>&secretKey=<secretKey>&shareKey=<shareKey>")`；`data`/`secretKey` 的 hex 大小写不同会产生完全不同的摘要。原文客户端输出小写 hex，复现端若输出大写（或其他库的默认编码不同）就会验签失败，修复方式是签名前统一转小写。
  - 注意：原文称 "Python `bytes.hex()` 默认大写"，但 Python 3 的 `bytes.hex()` 实际返回小写；实际大写可能来自其他库的 `hex()` 实现或显式 `.upper()`。结论"签名前统一 hex 大小写"仍成立，具体来源需按复现代码确认。
- SM2 还有两个易错点：
  - 密文模式：C1C2C3 与 C1C3C2 不同；不同库默认不同，原文客户端代码与协议摘要图对模式的描述也存在矛盾，必须以抓包/客户端实现为准；
  - 明文编码：`shareKey` 是 UTF-8 字符串的字节（先 `utf8ToHex` 再转字节数组），不是把 32 位 hex 直接 hex-decode 成 16 字节；搞错会导致 C2 完全不同。
- KDF 输入：gmssl 的 `sm3_kdf` 接收 `xy.encode("utf8")` 后内部 `bytes.fromhex` 得到 x2||y2 的 64 字节原始值，再拼接计数器迭代 SM3；与 JS 端一致时 KDF 输出才一致。

## 触发条件

- 使用 Python gmssl（或其他 SM2 库）复现客户端 SM2 加密/解密。
- 公钥 X 坐标以 `0` 或 `4` 开头（触发 lstrip 前缀 bug）。
- 签名串中的 hex 大小写与客户端不一致。
- 密文模式或明文编码与客户端不一致。

## 利用步骤

1. 取客户端公钥（130 hex，带 `04` 前缀），确认 X/Y 坐标；不要用 `lstrip`，用切片 `pub[2:]` 或先 `bytes.fromhex(pub)` 再取 `[1:]`。
2. 用已知测试向量验证曲线点解析：解析出的 X/Y 应与公钥字符串对应。
3. 统一 hex 大小写：在拼签名串之前对所有密文/密钥字段做 `.lower()`（或按客户端实际输出统一）。
4. 确认 SM2 密文模式（C1C2C3/C1C3C2）与明文编码（UTF-8 字符串字节 vs hex 解码）。
5. 用客户端生成的一组明文/密文做交叉验证：先用私钥或已知 shareKey 解密客户端密文，确认逐字节一致。
6. 若服务端对 SM2 密文兼容性差，可改为"请求体不变时复用原始 secretKey"，避免重新做 SM2 加密。

## PoC

```python
# 错误：lstrip 把 "04" 当字符集合
pub = "040AE4C7..." + "..."  # 130 hex
wrong = pub.lstrip("04")     # -> "AE4C7..."，丢失 X 开头的 0
right = pub[2:]              # -> "0AE4C7..."，正确

# 更稳妥：按字节处理
pub_bytes = bytes.fromhex(pub)
assert pub_bytes[0] == 0x04
x, y = pub_bytes[1:33], pub_bytes[33:65]
```

```python
# 签名前统一小写（按客户端实际编码调整）
data_hex = data_hex.lower()
secret_key_hex = secret_key_hex.lower()
share_key_hex = share_key_hex.lower()
sign_src = f"data={data_hex}&secretKey={secret_key_hex}&shareKey={share_key_hex}"
sm_sign = sm3_hash(sign_src)
```

```python
# 交叉验证：同一明文加密结果应与客户端可互相解密
# 注意模式：C1C2C3 / C1C3C2 需与客户端一致
```

说明：PoC 为原文坑点的最小复现，未在本机执行；gmssl 版本差异可能导致 `lstrip` 行为不同，需以实际库源码为准。

## 变体与关联

- 变体：其他语言的 SM2 库对公钥前缀、密文模式、ASN.1 编码的默认处理不同；跨语言复现应先用测试向量对齐，而不是直接套库默认值。
- 变体：SM3 签名串中字段顺序、分隔符、是否 URL 编码都会影响结果；以客户端代码为准。
- 变体：`shareKey` 作为 SM4 密钥时是 16 字节（32 hex），作为 SM2 明文时是 UTF-8 字符串字节，两种用法不要混淆。
- 关联：[[mobile-miniprogram-sm-crypto-protocol-burp-transparent]]（完整小程序国密协议逆向）；[[crypto-prng-math-random-sharekey-recovery]]（shareKey 的恢复）。
- 边界：本卡是复现/实现层面的坑点，不是目标系统的漏洞；若客户端使用标准库且实现一致，则不会触发。

## 检测与防御

- 检测（测试方）：SM2 解密结果长度异常、曲线点解析报错、SM3 验签恒定失败但密钥正确时，优先检查公钥前缀处理、hex 大小写、密文模式与明文编码。
- 防御（开发方）：使用经过审计的国密库，不要自行处理公钥前缀；对签名输入做规范化并写测试向量；跨语言实现时以官方测试向量和端到端互解验证为准。
- 加固：协议设计上避免把 hex 字符串直接拼进签名（用长度前缀/结构化编码），减少大小写与编码歧义。

