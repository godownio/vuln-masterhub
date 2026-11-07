---
id: code-analysis-reverse-obfuscation-cryptojs-wordarray-key-restore
title: 混淆 JS 中 CryptoJS WordArray 数值数组还原 key/iv 与 AES-CFB 参数还原
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: cryptojs-wordarray-key-restore
aliases:
- CryptoJS WordArray 还原
- words 数组转 key/iv
- sigBytes 密钥提取
- AES-CFB 前端加密还原
- createEncryptor 参数分析
tags:
- javascript
- reverse
- aes
- cfb
- cryptojs
- wordarray
- obfuscation
- key-extraction
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V11
  verified_at: '2026-11-05T01:30:06+08:00'
  notes: 已对照原文及13张图核对：_0x26151a 为 8 word/sigBytes=32 的 WordArray，_0x5bb22c 含 4 word/sigBytes=16 的 iv；大端还原 key=8AYNHzZ1okFUp2NCOm9mwYiQM46XJYFQ、iv=GU4odvR2C6ftmTL9；断点读出 CFB/NoPadding；CyberChef AES-CFB 加密后 Base64 的密文与卡片一致，反向解密得 JSON。卡片另注明了原文中出现的另一组 key/iv（xfsTo.../8Ur8...）未纳入，但示例自洽。未在目标环境执行。
---

## 一句话结论

混淆 JS 用 CryptoJS 的 `WordArray` 对象（`{words:[32位整数...], sigBytes:N}`）传递 key/iv 时，可将 `words` 按大端序还原为字节串得到真实 key/iv；再在 `createEncryptor`/`mode`/`padding` 处断点读出算法参数（本例 AES-CFB、NoPadding），即可在 CyberChef 或脚本中复现加解密、改写请求。

## 原理

- CryptoJS 内部用 `WordArray` 表示二进制数据：`words` 是 32 位整数数组（每个元素对应 4 字节，大端序），`sigBytes` 是有效字节数。key 为 8 个 word 即 32 字节（AES-256），iv 为 4 个 word 即 16 字节。
- 混淆代码常把 key/iv 写成十进制整数数组，而不是明文字符串，肉眼无法直接识别；但运行时 `_0x26151a` 就是 WordArray，`_0x5bb22c` 是配置对象，含 `iv`、`mode`、`padding`、`init`。
- 还原方法：把每个 word 按 `to_bytes(4, 'big')` 拼接，取前 `sigBytes` 字节，再按 UTF-8/ASCII 解码；也可在 console 直接调用 `wordArray.toString(CryptoJS.enc.Utf8)`。
- `createEncryptor(key, cfg)` 是 CryptoJS AES 的典型入口；在 `mode`/`padding` 赋值处下断点或求值，可看到 `CFB` 与 `NoPadding`（本例），而不是默认的 CBC/PKCS7。模式/填充决定能否分段处理、是否需要 padding。
- 本例请求体先 AES-CFB/NoPadding 加密 JSON，再 Base64；CFB 是流模式，不需要填充，密文长度与明文一致。复现时必须使用相同 key、iv、mode、padding，否则结果不可互换。
- 固定不变的 key/iv（多次请求数组值一致）说明密钥写死在前端；安全上等价于公开，只用于混淆而非保密。

## 触发条件

- 前端对请求/响应参数做对称加密，key/iv 存在于混淆 JS 中；
- key/iv 以 CryptoJS `WordArray`（`words` 整数数组 + `sigBytes`）形式传递；
- 攻击者能在 DevTools 中断点/console 求值，且能触发一次加密请求；
- 后端未对密文做额外签名/会话绑定，或攻击者可在同一会话内重放。

## 利用步骤

1. 搜索 `encrypt`/`createEncryptor` 等关键字，定位加密入口；在 `createEncryptor(keyWA, cfg)` 处下断点。
2. 打印 key 与 cfg：确认 key 是 `{words: Array(8), sigBytes: 32}`，cfg 含 `iv: {words: Array(4), sigBytes: 16}`、`mode`、`padding`。
3. 将 `words` 数组按大端 32 位转字节，再按 UTF-8 解码，得到 key/iv 字符串；也可用 AI/脚本批量转换。
4. 单步到 `mode`/`padding` 赋值处，或者 console 求值 `_0x...['mode']`/`_0x...['padding']` 的 toString，读出 `CFB`、`NoPadding`。
5. 在 CyberChef/Burp/Crypto 库中配置 AES-CFB、NoPadding、相同 key/iv，对抓包密文 Base64 解码后解密，得到明文 JSON。
6. 修改 JSON 后重新加密/Base64，替换请求体发送；若一次请求包含多段密文（如 key 与 iv 分开），逐段处理。

## PoC

```python
def words_to_bytes(words, sig_bytes):
    raw = b''.join(w.to_bytes(4, 'big') for w in words)
    return raw[:sig_bytes]

key_words = [943806798, 1215978033, 1869301333, 1882345027,
             1332558189, 2002348369, 1295267416, 1247364689]
iv_words  = [1196766319, 1685475890, 1127638644, 1834241081]

key = words_to_bytes(key_words, 32)   # b'8AYNHzZ1okFUp2NCOm9mwYiQM46XJYFQ'
iv  = words_to_bytes(iv_words, 16)    # b'GU4odvR2C6ftmTL9'
print(key, iv)
```

```python
# AES-CFB / NoPadding，密文先 Base64
import base64
from Crypto.Cipher import AES

ct = base64.b64decode("q2eQvlpetJVKmo6WByqgYbJm+LqwRfLW8U7mlEP8+u2wIRxxnyTG/OC/NYB5utraKyo=")
pt = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(ct)
print(pt.decode())  # {"page":1,"size":10,"examName":"","categoryId":""}
```

```text
# CyberChef 配方：From Base64 -> AES Decrypt (CFB, NoPadding, key/iv 同上)
```

## 变体与关联

- 变体：key/iv 每次随机时，会在请求中携带 RSA/ECDH 加密的密钥字段；此时在 JS 断点处直接读明文 WordArray 更简单。
- 变体：WordArray 的 `words` 也可能是小端或已按 `sigBytes` 截断；以实际 `toString(enc.Utf8)` 结果为准，不要盲目按大端转换。
- 变体：AES-GCM 的 tag、CBC 的 PKCS7 填充、3DES 等需按实际 mode/padding 调整；CFB 的 `segment_size` 需与实现一致。
- 关联：[[code-analysis-reverse-obfuscation-js-aes-parameter-restore]]（AES-CBC + iv||密文 的同类逆向，覆盖字符串 key 与随机 IV 场景）；[[web-generic-auth-js-signature-jsrpc-autodecoder]]（签名而非加密的运行时复用）。
- 边界：混淆只增加阅读成本；若加密在 WebAssembly/原生层完成，需动态调试或 hook。

## 检测与防御

- 检测：前端 bundle 中出现 `createEncryptor`、`WordArray`、`sigBytes`、大量十进制整数数组；请求体为 Base64 且明文长度与密文相近（CFB/CTR 流模式特征）。
- 检测：同一客户端多次请求的密文前若干字节不变（固定 IV）——CFB/CTR 下相同 IV+key 会泄露明文前缀异或关系。
- 防御：前端密钥一律视为公开，不能用于保密或身份认证；传输安全依赖 TLS。
- 防御：需要完整性时使用 AEAD（AES-GCM）或 HMAC，并绑定会话/时间戳/nonce；IV 必须随机且不可复用（尤其 CFB/CTR）。
- 防御：服务端对解密后的参数做权限与业务校验，不因“已加密”而信任。
