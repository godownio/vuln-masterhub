---
id: code-analysis-reverse-obfuscation-grandoreiro-string-decryption-triple-base64-diff-xor-aes
title: Grandoreiro 字符串解密：三次 Base64 密钥 + 自定义 hex/差分异或 + AES-256-CBC（密钥与 IV 同样加密）
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: grandoreiro-string-decryption-triple-base64-diff-xor-aes
aliases:
- Grandoreiro 字符串解密
- 三次 Base64 密钥
- 差分异或解密
- Grandoreiro AES CBC
- 银行木马字符串加密
- zf_decrypt_string
tags:
- malware-analysis
- reverse
- obfuscation
- string-encryption
- grandoreiro
- base64
- xor
- aes
- delphi
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V336
  verified_at: '2026-11-08T19:21:50+08:00'
  notes: 已对照原文与图 9-11/25 核对：图 9 IDA switch 的字符→常量（UStrCat、注释 G/X/E/F/C/H/B/D）与卡一致；图 10 差分算法 n=cipher[i]^key[(i-1)%len]; c=cipher[i-1]; c=n-c if c<n else n+0xff-c 与卡 PoC 逐行一致；图 11 密钥三次 Base64→Grandoreiro key、AES 256bit key/128bit IV 自定义解密、AES 解密到明文的流程图与卡一致；图 25 木马侧 key"A"/scrambler→AES ECB→自定义解码→旧算法的变体流程也与卡一致。卡已正确注明正文简化 XOR 与反编译差分算法的差异。原文无样本版本，已 --clear。dedup 仅自匹配；dup-scan(19:10)无涉及本卡的 pair。无 sources/URL/文章 ID。
---

## 一句话结论

Grandoreiro 加载器把主密钥硬编码为三次 Base64 编码的字符串，运行时三次 Base64 解码后再按十六进制转字节；加密字符串先经自定义解码（字符到常量的映射/hex 还原）变成密文字节，再用旧 Grandoreiro 差分异或算法解密；AES 密钥与 IV 也以加密字符串存储，用同一算法解出（跳过 AES），最后用 AES-256-CBC 解密并去填充得到明文。最终载荷 Grandoreiro 木马使用变体：AES ECB 模式 + 密钥 “A”/scrambler，再走自定义解码与旧算法，保护 10,000+ 字符串。

## 原理

- **主密钥存储**：样本中硬编码一个以 `D9JL@2]790B{P_D}Z-MXR&EZLI%3W>#VQ4UF+O6XVWB16713NIO!E…` 开头的字符串，经过三次 Base64 编码。运行时先做三次 `base64.b64decode`，得到十六进制字符串，再 `bytes.fromhex` 得到主密钥字节。
- **自定义解码**：加密字符串不是直接把 hex 交给算法，而是先经过一层自定义解码：IDA 中可见 switch 把 `!`、`"`、`#`、`$`、`%`、`&`、`)` 等字符映射到不同的常量字符串，用 `UStrCat` 拼接，最终还原成十六进制字符串。也就是“字符替换/查表 → hex 字符串 → bytes”。
- **旧 Grandoreiro 算法**：反编译图给出的 Python 等价实现是逐字节的“异或 + 差分/0xff 取模”：
  - `n = cipher[i] ^ key[(i-1) % len(key)]`
  - `c = cipher[i-1]`
  - `c = n - c if c < n else n + 0xff - c`
  - `plain += chr(c)`
  注意循环从 `i=1` 开始，使用前一个密文字节参与差分，因此不是简单逐字节 XOR。原文正文给出的 Python 是简化版“逐字节 XOR”，与反编译图不一致；实际样本应以图中差分算法为准。
- **AES 密钥/IV**：AES-256 的 key 与 128-bit IV 也以加密字符串形式存储；用同一套“自定义解码 + 旧算法”解出（跳过 AES 解密），再用于 AES-256-CBC 解密主密文。
- **解密顺序**：密文 → 自定义解码 → hex → 旧算法 → （对 AES key/IV 同样处理）→ AES-256-CBC 解密 → 去 padding → 明文字符串。
- **木马变体**：最终 Grandoreiro 载荷的字符串解密与加载器不同：用 key “A”/scrambler 经自定义加密得到 AES key，密文经自定义解码 → AES ECB 模式解密 → 再一次自定义解码 → 旧 Grandoreiro 算法 + 主密钥解密；字符串数量超过 10,000，分散在 100+ 个字符串加载函数中。
- **为什么这样设计**：多层编码把明文常量拆成“Base64 密钥 + 查表 + 差分 + AES”，静态字符串搜索和简单 XOR 扫描都失效；主密钥只出现一次（三次 Base64），AES key/IV 二次加密，逆向者必须还原完整链路才能批量解密。

## 触发条件

- 拿到 Grandoreiro 加载器/木马样本，定位到主密钥字符串与 `zf_decrypt_string`/字符串加载函数。
- 能从反编译代码还原自定义解码的字符映射表（switch/常量）。
- 知道算法版本（加载器 CBC 还是木马 ECB 变体）；不同样本密钥/映射可能不同。
- 有 Python/脚本环境做批量解密。

## 利用步骤

1. 在样本中搜索三次 Base64 的密钥字符串（前缀 `D9JL@2]...` 只是示例，样本间可能不同）。
2. 实现 `decode_key`：三次 Base64 解码 + `bytes.fromhex` 得到主密钥。
3. 从 IDA 的 switch 还原自定义解码表：字符 → 常量字符串；用 `UStrCat` 拼接结果得到 hex 字符串。
4. 实现旧算法（差分异或）解密 hex 密文；先用它解出 AES key/IV 的加密字符串（跳过 AES）。
5. 用解出的 key/IV 对主密文做 AES-256-CBC 解密，去除 PKCS#7 填充，得到明文。
6. 对木马变体：按 AES ECB + key “A”/scrambler 的路径先解 AES key，再 AES ECB 解密，再自定义解码 + 旧算法。
7. 批量跑样本中的字符串加载函数，生成明文列表用于 IOC/行为分析。

## PoC

原文给出的密钥解码（未在本机对真实样本执行）：

```python
import base64

def decode_key(key):
    # 三次 Base64 解码
    key = base64.b64decode(base64.b64decode(base64.b64decode(key)))
    # 十六进制字符串 -> bytes
    key = bytes.fromhex(key.decode())
    return key
```

反编译图对应的差分算法：

```python
def decrypt(ciphertext, key):
    plain = ''
    cipher = bytes.fromhex(ciphertext)
    for i in range(1, len(cipher)):
        n = cipher[i] ^ key[(i - 1) % len(key)]
        c = cipher[i - 1]
        c = n - c if c < n else n + 0xff - c
        plain += chr(c)
    return plain
```

原文正文的简化 XOR 版本（仅作对照，实际以差分算法为准）：

```python
def decrypt_string(encrypted_string, key):
    return ''.join(chr(encrypted_string[i] ^ key[i % len(key)])
                   for i in range(len(encrypted_string)))
```

## 变体与关联

- **加载器 vs 木马**：加载器用 AES-256-CBC；木马用 AES ECB + key “A”/scrambler，并多一层自定义解码。
- **其他银行木马字符串加密**：Dridex 的 API hash/CRC32 XOR、VBE/PowerShell 多层、.NET 双 Base64+AES 等；本卡的多层“三次 Base64 密钥 + 查表 + 差分 + AES”组合是 Grandoreiro 的特征。
- **YARA/检测**：可匹配三次 Base64 密钥前缀、`zf_decrypt_string`/`zf_get_encrypted_string8` 函数名、AES CBC/ECB 常量、字符映射 switch 模式。
- **批量解密**：把算法封装为 IDA 脚本/Unicorn 模拟调用字符串加载函数，避免手工还原每个映射表。

## 检测与防御

- **静态检测**：样本中出现三次 Base64 的长密钥字符串、hex 解码 + 差分异或循环、AES-256-CBC 常量、`zf_decrypt_string` 类函数名；可用 YARA 匹配密钥前缀与算法字节模式。
- **动态检测**：监控进程启动后大量字符串解密、AES 常量、内存中出现明文 C2/银行列表；沙箱记录解密后的字符串用于 IOC。
- **防御**：邮件网关拦截冒充税务/银行的 ZIP/EXE；终端阻止不明加载器；对 Delphi 样本做字符串解密与行为分析；更新 AV/EDR 特征。
- **逆向建议**：先定位主密钥与字符串加载函数，再按“自定义解码 → 旧算法 → AES”顺序实现；注意正文简化 XOR 与反编译差分算法的差异。
