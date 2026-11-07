---
id: ctf-reverse-miniprogram-variant-rc4-reverse-ksa
title: 微信小程序 VIN 校验变种 RC4 逆向：反向 KSA + 位置异或解密
type: scenario
domain: ctf
path: ctf/reverse
technique: miniprogram-variant-rc4-reverse-ksa
tags:
- ctf
- reverse
- miniprogram
- javascript
- rc4
- stream-cipher
- ksa
- prga
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V131
  verified_at: '2026-11-06T05:39:07+08:00'
  notes: 已对照原文 Reverse 部分与截图核对：verifyVinByRc4、correctEncrypted=7AF2C74EAD5C2D4505E94B820275CA8C52、密钥 Z1X3Y4E5Z8V2A6H6、正向+反向 KSA、PRGA K=S[(S[i]+S[j]+S[t])%256] 与位置异或均一致；按卡内 PoC 复算得 L0J6Q0P7H3E2I5U6H，与截图一致。
url: /docs/ctf/reverse/ctf-reverse-miniprogram-variant-rc4-reverse-ksa/
draft: false
kb_aliases:
- 小程序 RC4 变种
- 反向 KSA
- 位置异或 RC4
- verifyVinByRc4
- VIN 校验逆向
---

## 一句话结论

小程序把 VIN 校验写成“标准正向 KSA + 额外反向 KSA + PRGA 输出再异或位置索引”的变种 RC4，且密钥和期望密文都硬编码在页面 JS 中；把同一套变种逻辑复刻到解密脚本（异或自逆，加解密同函数）即可从十六进制密文还原 VIN。

## 原理

- **标准 RC4 骨架**：S 盒初始化为 `0..255`，KSA 用 `j = (j + S[i] + key[i % L]) % 256` 交换；PRGA 每字节 `i=(i+1)%256`、`j=(j+S[i])%256`、交换、`t=(S[i]+S[j])%256`，输出 `S[t]` 与数据异或。
- **第一处变种（反向 KSA）**：在正向 KSA 之后，再用同一公式从 `i=255` 递减到 `0` 做一遍交换，相当于对 S 盒再做一次逆序置乱；解密时必须同样执行两遍，否则密钥流不同。
- **第二处变种（位置异或）**：PRGA 输出不是 `S[t]`，而是 `K = S[(S[i] + S[j] + S[t]) % 256]`，并且最终密文为 `c = p ^ K ^ (k % 256)`，其中 `k` 是字节位置索引。位置项让相同明文在不同偏移得到不同密文，也增加了直接套标准 RC4 的失败概率。
- **为什么能解密**：整个过程只由异或和 S 盒置换组成，异或自逆；只要 S 盒初始化、两遍 KSA、PRGA 下标和位置项完全一致，同一个函数既能加密也能解密。
- **密钥与密文来源**：页面 JS 中 `correctEncrypted` 是十六进制期望值，密钥 `Z1X3Y4E5Z8V2A6H6` 作为第二个参数传入 `variantRC4Encrypt`；小程序包未加密时可直接在 `app-service.js`/页面 JS 中搜索 `verifyVinByRc4`、`correctEncrypted` 定位。

## 触发条件

- 拿到小程序包（wxapkg）或页面 JS，代码未加密/未混淆到不可读。
- 校验函数包含 256 项 S 盒、两次 256 次循环、`%256` 交换与异或，且与标准 RC4 有可见差异。
- 期望密文与密钥硬编码，或可通过已知明文/爆破恢复密钥。
- 密文以十六进制/字节数组形式给出，长度与 VIN 等明文一致。

## 利用步骤

1. 解包小程序，打开 `app-service.js` 或对应页面 JS，搜索 `verifyVinByRc4`、`correctEncrypted`、`variantRC4` 等关键字。
2. 记录密钥、期望密文、S 盒初始化、KSA 循环次数/方向、PRGA 下标公式、是否有位置异或。
3. 用 Python/JS 复刻同一套变种 RC4；先把十六进制密文转字节，再逐字节异或解密。
4. 输出可打印字符串，检查是否为 17 位 VIN 或 flag 格式；用同一函数重新加密，确认能得到原始密文。
5. 若密钥未知，利用已知 VIN 格式（17 位、字母数字）做已知明文攻击或按密钥空间爆破。

## PoC

```python
def ksa_variant(key):
    S = list(range(256)); j = 0; L = len(key)
    for i in range(256):                      # 正向 KSA
        j = (j + S[i] + key[i % L]) % 256
        S[i], S[j] = S[j], S[i]
    j = 0
    for i in range(255, -1, -1):              # 反向 KSA
        j = (j + S[i] + key[i % L]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def variant_rc4(data, key):
    S = ksa_variant(key)
    i = j = 0; out = bytearray()
    for n, b in enumerate(data):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256
        K = S[(S[i] + S[j] + S[t]) % 256]
        out.append(b ^ K ^ (n % 256))         # 位置异或
    return bytes(out)

ct = bytes.fromhex("7AF2C74EAD5C2D4505E94B820275CA8C52")
pt = variant_rc4(ct, b"Z1X3Y4E5Z8V2A6H6")
print(pt.decode())                            # 17 位 VIN
print("FLAG{" + pt.decode() + "}")
```

## 变体与关联

- 变体：反向 KSA 可能只做部分轮（如 128 轮）、或与正向 KSA 交换顺序；按代码逐处同步。
- 变体：位置项可能是 `k % 256`、`k`、`k ^ 常量` 或按块轮换；也可能是 `S[t] ^ k` 而非额外异或。
- 变体：密钥可能由多个常量拼接、按索引取模或从 `wx.getStorageSync` 读取；先静态定位，再动态 hook。
- 变体：密文可能是 Base64/十六进制/字节数组；小程序包可能被分包或压缩，需先还原 `app-service.js`。
- 关联：[[ctf-reverse-modified-rc4-rounds-sbox]]（魔改 RC4 的通用识别与同步）、[[mobile-miniprogram-sm-crypto-protocol-burp-transparent]]（小程序国密协议与透明加解密）。

## 检测与防御

- 检测（逆向）：JS 中出现 256 项数组、两次 256 循环、`%256` 交换、`correctEncrypted` 常量与 `verify*` 函数。
- 检测（防守）：客户端出现硬编码密钥、期望密文和自研流密码；相同 VIN 的密文固定、可离线验证。
- 防御：不要用客户端校验作为唯一授权依据；VIN/业务校验放服务端，客户端只做格式检查。
- 防御：使用标准密码库（WebCrypto AES-GCM/ChaCha20-Poly1305），密钥放服务端或安全存储；自定义 RC4 变种不构成安全增强。
- 边界：若小程序代码被强混淆/加密，先做解包与反混淆；若密钥动态下发，需要结合网络协议与运行时 hook。
