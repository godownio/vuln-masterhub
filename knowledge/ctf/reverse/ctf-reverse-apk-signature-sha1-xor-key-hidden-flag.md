---
id: ctf-reverse-apk-signature-sha1-xor-key-hidden-flag
title: APK 签名 SHA1 作异或密钥：还原被 UI 隐藏的 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: apk-signature-sha1-xor-key-hidden-flag
aliases:
- CodeSign
- 签名校验异或解密
- PackageManager GET_SIGNATURES
- APK 签名 SHA1 密钥
- UI OUTPUT DISABLED
tags:
- reverse
- android
- apk
- jadx
- signature
- sha1
- xor
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:44:26+08:00'
  notes: 已对照原文 CodeSign 反编译代码核对：SECRET_DATA、getAppSignature→SHA1→小写hex(40字符)、XOR解密逻辑与原文一致；原文未直接给出flag明文，未本机复跑。注意：按 jadx lambda 参数传递顺序，setText 可能落在 tv_flag 上，与题面 UI 隐藏叙述略有出入，属原文细节。
---

## 一句话结论

APK 的解锁按钮用 `SignUtils.getAppSignature()` 取应用签名证书的 SHA1 十六进制串作为密钥，与硬编码的 `SECRET_DATA` 逐字节异或；解密结果以 `flag{` 开头时 UI 只显示 “ACCESS GRANTED / UI OUTPUT: DISABLED”，真正的明文并不显示，因此需要从 JADX 中取出签名 SHA1 并离线重跑异或还原 flag。

## 原理

- **密钥来源**：`getAppSignature(Context)` 调用 `PackageManager.getPackageInfo(packageName, 64).signatures[0].toByteArray()`，其中 64 是 `GET_SIGNATURES` 常量；`hex()` 对该字节数组做 SHA1，再把 20 字节摘要转成小写十六进制字符串（40 字符）。
- **解密算法**：`decrypt(byte[] data, String key)` 用 `key.getBytes()` 的字节循环异或 `data[i] ^ keyBytes[i % keyLen]`；密钥是十六进制字符串本身，不是摘要原始字节。
- **UI 逻辑**：解密结果 `startsWith("flag{")` 时只把 `tv_flag` 设成 “ACCESS GRANTED / DATA RENDERED TO BUFFER / UI OUTPUT: DISABLED”，不显示明文；因此不能靠点按钮拿 flag，必须离线解密。
- **签名可静态获取**：JADX 中签名 SHA1 以字节数组形式出现（如 `0F BF 65 80 2A 94 64 9F ...`），转十六进制小写即可作为密钥；签名是 APK 自带证书的公开信息，不涉及私钥。
- **为什么异或可逆**：`cipher[i] = data[i] ^ key[i%n]`，再次异或同一密钥即还原；密钥长度 40，循环使用。

## 触发条件

- Android 应用把解密密钥绑定到自身签名（SHA1/证书哈希/包名等）。
- 加密数据硬编码在 DEX/资源中，算法为简单异或/流式异或。
- 解密结果只用于本地判断（如 `startsWith("flag{")`），明文不直接展示或被 UI 隐藏。
- 攻击者能静态反编译 APK 并读取签名信息。

## 利用步骤

1. 用 JADX/apktool 反编译 APK，定位主 Activity 与关键解密函数。
2. 找到硬编码密文数组 `SECRET_DATA` 与解密算法（异或、密钥循环）。
3. 跟踪密钥来源：`getPackageInfo(..., 64).signatures[0].toByteArray()` → SHA1 → 小写十六进制。
4. 在 JADX 中读取签名 SHA1 字节数组，转成 40 字符十六进制字符串。
5. 离线重跑异或：`chr(data[i] ^ ord(key[i % len(key)]))`，得到以 `flag{` 开头的明文。
6. 若签名 SHA1 不易读，可用 `apksigner verify --print-certs`、`keytool -printcert` 或动态 Hook `getAppSignature` 获取。

## PoC

```python
secret = [
    86, 10, 3, 1, 77, 124, 123, 97, 109, 37,
    64, 90, 2, 89, 8, 5, 111, 115, 64, 66,
    4, 16, 65, 62, 123, 8, 88, 81, 30
]
key = "0fbf65802a94649f01920c2a0966c2934e817f73"

flag = ''.join(
    chr(b ^ ord(key[i % len(key)]))
    for i, b in enumerate(secret)
)
print(flag)
```

原文用该脚本还原出 flag；未在本机复跑。

## 变体与关联

- **密钥来源变体**：签名 SHA1、签名 MD5、证书公钥哈希、包名、版本号、device ID；静态提取或动态 Hook。
- **算法变体**：单字节 XOR、循环密钥 XOR、加减/异或混合、AES 密钥由签名派生。
- **隐藏方式变体**：UI 只显示成功/失败、明文写入日志但被过滤、比较后丢弃；需要改 smali 或离线复算。
- **关联**：[[mobile-android-apk-xor-string-batch-deobfuscation]]（APK 字符串异或批量还原）；本卡强调“签名哈希作为密钥 + UI 隐藏结果”。

## 检测与防御

- 不要把签名哈希/包名等公开信息当作秘密密钥；需要密钥时使用服务端下发或 Android Keystore。
- 敏感判断不要只在客户端做；flag/密钥不应硬编码在 APK 中。
- 检测：APK 中出现 `GET_SIGNATURES` + SHA1 + XOR 循环的组合；解密结果仅用于本地 `startsWith` 判断。
