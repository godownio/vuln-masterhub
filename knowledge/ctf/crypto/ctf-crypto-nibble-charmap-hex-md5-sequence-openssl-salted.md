---
id: ctf-crypto-nibble-charmap-hex-md5-sequence-openssl-salted
title: 自定义 4 位字符表编码的还原（每位十六进制 → 表内一个字符）+ 认出「连续 MD5(1)/MD5(2)/MD5(3)…」十六进制串作为钥匙，再处理 U2FsdGVkX1 开头的 OpenSSL Salted__ 密文
type: scenario
domain: ctf
path: ctf/crypto
technique: nibble-charmap-hex-md5-sequence-recover
aliases:
- 4 位字符表编码
- 半字节替换表
- char_map 自定义字符集
- 连续 MD5 数字串识别
- MD5(1)MD5(2)MD5(3) 拼接
- U2FsdGVkX1 双层密文
tags:
- crypto
- ctf
- encoding
- substitution
- md5
- openssl
- aes
- rabbit
- base64
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:34:58+08:00'
  notes: 已对照原文核对；char_map=BALUINGbaluing+-（16 字符，恰好 4 个半字节）、encode 按 format(int(char,16),04b) 每 4 位一字符、decode 反查拼回十六进制，均与正文代码一致；解码结果 c4ca4238a0b923820dcc509a6f75849b / c81e728d9d4c2f636f067f89cc14862c / eccbc87e4b5ce2fe28308fd9f2a7baf3 确为 MD5(1)/MD5(2)/MD5(3)，卡片「连续 MD5(序号) 串联」的识别判据成立；U2FsdGVkX1 ⇔ Salted__ + EVP_BytesToKey 的说明与正文「U2Fsd 开头应该是 AES 或 rabbit 解密」相符，卡片明确标注算法未定需逐个试，未把猜测写成结论；本次核对未读取图片，5 张图（题面、解码器、nc 交互）未读图核对，交互验证环节仅按正文文字复核；卡片未照抄 16 字符表常量与完整密文之外的敏感内容；未连接文中 nc、未执行 exp
---

## 一句话结论

当密文只由十几个固定字符组成、且长度是「十六进制串长度」的整数倍时，先怀疑「4 位分组 + 自定义字符表」编码：把每个字符按表查回 0–15 的索引、拼成十六进制串；若拼出的十六进制串恰好能按 32 位一组切开、且每组都像摘要，逐组比对 `MD5("1")`、`MD5("2")`、`MD5("3")`… 就能确认这是「序号 MD5 串联」形式的钥匙。得到十六进制/口令后，再处理主密文：以 `U2FsdGVkX1` 开头的 base64 就是 OpenSSL `Salted__` 结构（8 字节魔数 + 8 字节 salt + 密文），用同一口令走 `openssl enc -d` 或 `EVP_BytesToKey` 派生密钥即可解出。

## 原理

- **4 位分组编码相当于「十六进制换皮」**：明文先转十六进制（每个字节两个 hex 字符），再把每个 hex 字符（0–f，共 16 种）映射到自定义表里的一个字符。因此密文字符种类 ≤16、长度等于 hex 串长度、且能双射回 hex——这三点与「单表替换」「Base64」「Base32」都能区分开：Base64 有 64 种符号、长度是 4 的倍数且带 `=` 填充；Base32 是 32 种、长度 8 的倍数。
- **为什么十六进制串会「像摘要」**：`c4ca4238a0b923820dcc509a6f75849b` 是 `MD5("1")`，`c81e728d9d4c2f636f067f89cc14862c` 是 `MD5("2")`，`eccbc87e4b5ce2fe28308fd9f2a7baf3` 是 `MD5("3")`——出题人常把「1、2、3… 的 MD5 首尾相接」当作口令或密钥表，因为长度固定 32、字符集就是 `0-9a-f`，天然适合再套一层十六进制编码。识别方法很直接：按 32 位切片，逐片用 `md5(str(i))` 试探；命中即说明整串是序号摘要序列，而「序号」本身就是需要还原的语义（也可能需要继续拼成下一步的输入）。
- **`U2FsdGVkX1` 是 `Salted__` 的 base64 片段**：OpenSSL 的 `enc` 子命令在带 `-salt` 时输出 `Salted__`（8 字节）+ salt（8 字节）+ 密文，整体再做 base64，于是任何这种密文都以 `U2FsdGVkX1` 开头。这给出两层信息：KDF 是 OpenSSL 的 `EVP_BytesToKey`（旧版 MD5 派生、新版 `-pbkdf2` 走 PBKDF2），以及密文长度必须是 `16 + 16n`（AES-CBC）或与流密码等长。
- **两层之间是「口令」而非「密钥」**：第一层解出的十六进制/摘要串通常充当第二层的口令（passphrase），由 `EVP_BytesToKey` 结合 salt 派生出真正的 AES key/IV。这也是为什么必须先还原第一层：没有口令就无法派生密钥，salt 不能替代口令。
- **为什么两种可能都要试**：`Salted__` 只锁定「salt 布局与 KDF」，不锁定算法。可能是 AES-128/192/256-CBC、也可能是 rabbit/bf/des3；先按 AES-256-CBC 试，失败再换算法，用「解出的前若干字节是否为可打印/是否含 flag 前缀」作判据。

## 触发条件

- 密文 1：字符种类很少（十几到二十几种）、长度与 hex 串等长，且题面/反编译代码里能看到一张自定义字符表（形如 `"BALUINGbaluing+-"` 这类大小写混合的 16–18 字符常量）。
- 密文 2（或同一题的另一段）：base64 文本以 `U2FsdGVkX1` 开头，解码后前 8 字节为 `Salted__`。
- 存在一个交互端（nc 服务）要求提交还原结果作为钥匙/口令，构成「解码 → 交互 → 继续」的闭环。
- 有 OpenSSL 或 Python `cryptography`/`Crypto` 可用于离线派生与解密。

## 利用步骤

1. 统计密文字符种类与长度：若 ≤16 种且长度恰为偶数，按 4 位分组模型处理；若 64 种且长度是 4 的倍数，考虑 Base64。
2. 找到字符表常量（源码/题面/注释里的字符串）。表长 16 即标准半字节表；表长 18（含 `+`、`-` 两个额外符号）说明只是把 16 个索引映射到表的前 16 项，多余符号不参与编码。
3. 用逆表把密文逐字符换回索引，按 4 位二进制（或直接一位 hex）拼出十六进制串。
4. 按 32 位切片试探 `md5(str(i))`；若逐片命中 `1,2,3,…`，把这些序号记录下来（往往就是需要提交的「密码」或下一步口令）。
5. 处理主密文：base64 解码，断言前 8 字节为 `b"Salted__"`，取 `salt = raw[8:16]`、`ct = raw[16:]`；长度断言为 `16 + 16n` 则按 AES-CBC 处理。
6. 用第 4 步得到的口令派生密钥并解密（`openssl enc -d -aes-256-cbc -salt` 或自己实现 `EVP_BytesToKey`）；失败则换算法（rabbit / aes-128-cbc / des3）或换 `-pbkdf2`。
7. 解开后按题目要求把结果提交给交互端，验证是否通过。

## PoC

第一层：半字节字符表反向还原成十六进制：

```python
class NibbleMap:
    def __init__(self, table):
        self.table = table                       # 例："BALUINGbaluing+-"
        self.index = {c: i for i, c in enumerate(self.table)}

    def decode(self, cipher):
        bits = ''.join(format(self.index[c], '04b') for c in cipher)
        return ''.join(format(int(bits[i:i+4], 2), 'x') for i in range(0, len(bits), 4))

print(NibbleMap("BALUINGbaluing+-").decode(CIPHER))
# 输出形如 c4ca4238a0b923820dcc509a6f75849bc81e728d9d4c2f636f067f89cc14862c...
```

第二层：确认「连续 MD5(序号) 串联」：

```python
import hashlib
hexstr = NibbleMap("BALUINGbaluing+-").decode(CIPHER)
parts = [hexstr[i:i+32] for i in range(0, len(hexstr), 32)]
for i, p in enumerate(parts, 1):
    if p == hashlib.md5(str(i).encode()).hexdigest():
        print("hit", i)          # 1,2,3... 命中即确认结构
```

第三层：OpenSSL `Salted__` 解包与解密：

```python
import base64
raw = base64.b64decode(b64)
assert raw[:8] == b"Salted__"
salt, ct = raw[8:16], raw[16:]
assert (len(ct) - 16) % 16 == 0 or len(ct) % 16 == 0

# 或直接用 openssl（口令来自第一层）
# openssl enc -d -aes-256-cbc -salt -in enc.bin -out plain.txt -pass pass:<口令>
```

## 变体与关联

- 表长变体：16 字符纯数字表、18 字符带 `+/-` 表、大小写混排表；只要表里前 16 项与索引一一对应即可反查，多余符号忽略。
- 摘要序列变体：`MD5(1..n)` 换成 `SHA1(1..n)`（长度 40 切片）、`MD5("admin")` 之类固定词、或「每个字符的 MD5」；切片长度是首要判据。
- 外层变体：`U2FsdGVkX1` 之后也可能是 rabbit/bf/des3/`-pbkdf2` 派生；同一 `Salted__` 头对应多种算法，需按可读性逐个试。
- 关联：[[crypto-classical-lookup-table-multibyte-substitution-reverse]]（同类「查表还原」但单位是多字节字符）、[[ctf-crypto-custom-base64-charset-oracle-recovery]]（自定义字符集 + oracle 恢复）、[[ctf-crypto-tianshu-foshuo-double-layer-cryptojs-evp-bytes-to-key]]（`U2FsdGVkX1`/`Salted__` 与 `EVP_BytesToKey` 的完整双层流程）。

## 检测与防御

- 本题为 CTF 编码/口令还原，无软件漏洞；「防御」等价于识别：
  - 自研字符表编码不具机密性——字符种类、长度与双射关系即可判定，属编码而非加密。
  - `MD5(1..n)` 这类可预测摘要串不能当密钥材料；真实系统中口令/密钥必须来自 CSPRNG 并配 KDF（PBKDF2/scrypt/Argon2）+ 足够熵的 salt。
  - OpenSSL `Salted__` 格式本身不含认证，无法防篡改；生产环境应使用 AEAD（AES-GCM）或加 HMAC。
- 检测信号：固定字符表常量出现在二进制/脚本中；密文熵低但长度与 hex 对齐；密文以 `U2FsdGVkX1` 开头（说明用了 `openssl enc -salt` 的默认输出）。
