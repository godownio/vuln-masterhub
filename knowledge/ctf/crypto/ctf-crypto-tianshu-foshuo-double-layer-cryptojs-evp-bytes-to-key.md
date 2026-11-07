---
id: ctf-crypto-tianshu-foshuo-double-layer-cryptojs-evp-bytes-to-key
title: 天书 + 与佛论禅双层中文编码：64 符号 base64 变体与 128 字表高位标志，套 CryptoJS EVP_BytesToKey AES
type: scenario
domain: ctf
path: ctf/crypto
technique: tianshu-foshuo-cryptojs-evp-bytes-to-key
aliases:
- 天书编码
- 与佛论禅
- 佛曰
- 中文编码套娃
- CryptoJS Salted__ 解密
- EVP_BytesToKey
tags:
- crypto
- encoding
- base64
- aes
- cryptojs
- evp-bytes-to-key
- chinese-encoding
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:46:30+08:00'
  notes: 已对照原文核对；64 符号与长度算术、U2FsdGVkX1 前缀回补、EVP_BytesToKey MD5、12 标志字 +128 逻辑均一致
---

## 一句话结论

密文只有 64 种符号且混有一个裸 `+`，说明外层是“天书”——把 CryptoJS 的 base64 输出按 64 字表替换并截掉固定前缀 `U2FsdGVkX1`；逆替换、补回前缀并 base64 解码后得到 OpenSSL `Salted__` 结构，用 `EVP_BytesToKey`（MD5）派生 AES 密钥解出内层“与佛论禅”，再按 128 字表与 12 个高位标志字逐字还原字节，得到 UTF-16LE 明文。

## 原理

- **先做算术定结构**：密文 310 个符号，加回被截掉的 10 字符前缀 `U2FsdGVkX1` 得 320；`320 * 6 / 8 = 240` 字节；`240 = 8（Salted__ 魔数）+ 8（salt）+ 224（14 个 AES 块）`，整除且无 `=` 填充。`Salted__` 只出现在 OpenSSL/CryptoJS 的 `EVP_BytesToKey` 格式里，KDF 基本被锁定。
- **区分两种中文编码**：与佛论禅用 128 字表 + 12 个高位标志字，逐字节映射；天书是 64 字表（base64 字母表的汉字替换），常截掉固定前缀。本题 64 种符号，落在天书一侧。
- **天书是可逆替换**：字符表必须拿到原表（顺序任意）；AES 输出近似随机，没有统计抓手。用逆表把每个汉字换回 base64 字符，补回 `U2FsdGVkX1`，解码后断言前 8 字节为 `Salted__`。
- **EVP_BytesToKey**：`prev = MD5(prev + password + salt)` 迭代，拼接输出直到 48 字节；前 32 字节为 AES-256 key，后 16 字节为 IV（本题口令 `BlackCat184`）。
- **与佛论禅高位标志**：128 字表只覆盖 0–127；遇到 12 个标志字之一时，跳过标志字并把下一个字的表索引加 128，才能得到高位字节。漏掉标志字逻辑会让字节流高位全错，AES 填充校验必然失败——填充失败本身就是标志字没处理对的信号。
- **套娃结构**：第一层解出文本仍以“佛曰：”开头；第二层按与佛论禅规则还原字节，明文编码是 UTF-16LE（按 UTF-8 解会看到隔位零字节）。

## 触发条件

- 密文由中文异体字组成，带“曰：”或“佛曰：”前缀。
- 符号种类为 64 或 128+，可据此判断是天书还是与佛论禅。
- 解码后出现 `Salted__` 或长度符合 `8 + 8 + 16n` 的块结构。
- 需要原版字符表/工具常量（key、iv 或口令）；顺序不能靠猜。

## 利用步骤

1. 统计符号种类与长度：本题 310 符号、64 种、63 汉字 + 1 个裸 `+`；裸 `+` 是字母表锚点，说明工具漏替换了 `+`。
2. 做长度算术：`(310 + 10) * 6 / 8 = 240 = 8 + 8 + 224`，判定为 `Salted__ + salt + 14 块 AES`。
3. 判定外层为天书：64 字表；用逆表把 body 换回 base64，前置 `U2FsdGVkX1`。
4. base64 解码，断言 `raw[:8] == b"Salted__"`；取 `salt = raw[8:16]`、`ct = raw[16:]`。
5. 用 `EVP_BytesToKey`（MD5，口令 `BlackCat184`）派生 48 字节，AES-256-CBC 解密并去 PKCS#7 填充，得到内层“佛曰：”文本。
6. 与佛论禅层：用 128 字表逐字取索引；遇到 12 个标志字（冥、奢、梵、呐、俱、哆、怯、諳、罰、侄、缽、皤）时，下一字索引 +128。
7. 把字节按 UTF-16LE 解码，得到 flag。

## PoC

天书逆替换 + EVP_BytesToKey：

```python
INV = {v: k for k, v in TABLE.items()}
b64 = "U2FsdGVkX1" + "".join(INV[c] for c in body)
raw = base64.b64decode(b64)
assert raw[:8] == b"Salted__"
salt, ct = raw[8:16], raw[16:]

def evp(pw, salt, n=48):
    out, prev = b"", b""
    while len(out) < n:
        prev = hashlib.md5(prev + pw + salt).digest()
        out += prev
    return out[:n]

k = evp(b"BlackCat184", salt)
layer1 = AES.new(k[:32], AES.MODE_CBC, k[32:]).decrypt(ct)
layer1 = layer1[:-layer1[-1]].decode()
```

与佛论禅标志字处理：

```python
MARK = set("冥奢梵呐俱哆怯諳罰侄缽皤")
data = bytearray()
i = 0
while i < len(body):
    if body[i] in MARK:
        i += 1
        data.append(TABLE.index(body[i]) + 128)
    else:
        data.append(TABLE.index(body[i]))
    i += 1
```

原文最终得到 `flag{zifu_jiami_678}`；未在本机复跑。

## 变体与关联

- **编码变体**：与佛论禅（128 字表 + 高位标志）、天书（64 字表）、新佛曰等；区分关键是字典规模与前缀。
- **KDF 变体**：CryptoJS 默认 `EVP_BytesToKey` MD5、OpenSSL `-md sha256` 等；口令、迭代次数与摘要需从工具或题面确认。
- **AES 模式**：CBC 之外还可能是 CTR/CFB；`Salted__` 只说明 KDF 与 salt 布局，不锁定模式。
- **关联**：与“古典密码/替换表”“多层编码套娃”同类；本卡的价值在于把长度算术、表规模判定、KDF 识别串成一条可复现流程。

## 检测与防御

- 取证/解题侧：先做长度与符号种类统计，再决定查哪张表；不要凭“佛说”字样直接套与佛论禅，64 字表说明是天书。
- 防护侧：这类编码只是混淆，不是加密；敏感数据不要用固定口令 + `EVP_BytesToKey` 的弱 KDF，应使用 Argon2/scrypt/PBKDF2 + 随机 nonce + AEAD。
- 检测特征：中文异体字密文、64/128 符号种类、`U2FsdGVkX1`/`Salted__`、固定口令常量、AES-CBC 块长度。
