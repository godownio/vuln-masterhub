---
id: mobile-android-apk-signature-sha1-xor-key-decrypt
title: APK 签名校验逆向：用应用签名 SHA1 作为 XOR key 解密内置密文
type: scenario
domain: mobile
path: mobile/android
technique: apk-signature-sha1-xor-key-decrypt
tags:
- android
- apk
- reverse
- signature
- sha1
- xor
- jadx
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T02:12:51+08:00'
  notes: 已通读原文 CodeSign 段并核对：MainActivity 的 SECRET_DATA 29 字节、decrypt 逐字节 bArr[i]^keyBytes[i%keyLen]、getAppSignature 用 getPackageInfo(pkg,64).signatures[0].toByteArray()、hex 用 MessageDigest SHA1 后逐字节两位小写 hex、jadx 取得签名 SHA1 0fbf65802a94649f01920c2a0966c2934e817f73、PoC 与该 key 逐字节异或均一致。原文未贴最终明文字符串，卡片已注明需本地复算；签名是公开信息、不能作密钥的结论正确。未在本机复跑；无组件版本。
url: /docs/mobile/android/mobile-android-apk-signature-sha1-xor-key-decrypt/
draft: false
kb_aliases:
- APK 签名校验
- getAppSignature
- GET_SIGNATURES
- 签名 SHA1 作为密钥
- CodeSign
---

## 一句话结论

当 APK 用 `PackageManager.getPackageInfo(pkg, GET_SIGNATURES).signatures[0]` 取自身签名、SHA1 后作为 XOR key 解密内置 `SECRET_DATA`，并用“明文是否以 `flag{` 开头”决定 UI 提示时，逆向 `getAppSignature`/`hex` 与 `decrypt` 即可恢复 key 并解出 flag；签名是公开信息，不能作为秘密。

## 原理

- **签名获取**：`GET_SIGNATURES` 常量值为 `64`；`getPackageInfo(pkg, 64).signatures[0].toByteArray()` 返回 APK 签名证书的 DER 字节。
- **hex/SHA1**：`hex()` 对签名字节做 `MessageDigest.getInstance("SHA1").digest()`，再把每个字节转两位小写十六进制，得到 40 字符的 SHA1 字符串；该字符串的 ASCII 字节被用作 XOR key。
- **解密逻辑**：`decrypt(SECRET_DATA, signatureSha1)` 对每个密文字节 `bArr[i] ^ keyBytes[i % keyLen]`，得到明文字符串；若以 `flag{` 开头，则显示 `ACCESS GRANTED`（但 UI 输出被禁用，实际 flag 不直接显示）。
- **为什么能还原**：SHA1 是确定性的，签名固定则 key 固定；XOR 自逆，直接用同一 key 再异或即可解密。签名可从 APK 的 `META-INF/*.RSA`/`*.DSA`/`*.EC` 或 jadx 中获取，不需要私钥。
- **安全误区**：签名是公开可验证的，不是秘密；把签名当加密 key 只能防止“未重新签名”的简单篡改，攻击者重打包后签名变化，但也可以直接 patch 校验逻辑/提取 key。

## 触发条件

- APK 中有 `getPackageInfo(..., GET_SIGNATURES)`/`signatures[0]`、SHA1/hex、XOR 解密逻辑。
- 密文硬编码在 DEX/资源中；明文有可识别前缀（`flag{`）或格式。
- 能拿到 APK 的签名（原包 `META-INF` 或 jadx 展示）并计算 SHA1。
- 目标是离线还原 flag，或理解签名绑定校验；不需要绕过服务端。

## 利用步骤

1. 用 jadx/apktool 反编译 APK，定位 `MainActivity` 与 `decrypt`/`getAppSignature`/`hex`。
2. 确认 key 来源：`GET_SIGNATURES`（64）→ `signatures[0].toByteArray()` → SHA1 → 小写 hex 字符串。
3. 从 APK 的 `META-INF` 提取签名块，或从 jadx/运行时获取签名字节；计算 SHA1 并转 40 字符 hex。
4. 取 `SECRET_DATA` 字节数组，按 `secret[i] ^ ord(key[i % len(key)])` 解密，得到明文。
5. 用 `flag{` 前缀/可打印性验证；若签名不匹配，检查是否取错签名（多签名/旋转签名/v2/v3）或 hex 大小写。
6. 本题脚本得到一个 `flag{...}`；原文未在正文展示最终字符串，需按上述步骤本地复算。

## PoC

```python
secret = [
    86, 10, 3, 1, 77, 124, 123, 97, 109, 37,
    64, 90, 2, 89, 8, 5, 111, 115, 64, 66,
    4, 16, 65, 62, 123, 8, 88, 81, 30
]
key = "0fbf65802a94649f01920c2a0966c2934e817f73"  # 签名 SHA1 的小写 hex
flag = ''.join(chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(secret))
print(flag)
```

签名提取（概念）：

```text
APK = zip; META-INF/*.RSA|*.DSA|*.EC 是 PKCS#7 签名块
signatures[0].toByteArray() = 证书 DER
SHA1(DER) -> 20 字节 -> 小写 hex（40 字符）
```

## 变体与关联

- **变体（签名校验而非加密）**：比较当前签名 SHA1 与硬编码值，不等则退出；可 patch 比较或重签名后替换硬编码值。
- **变体（多签名/旋转）**：`signatures` 数组可能多个；v2/v3 签名方案下 `GET_SIGNATURES` 仍返回 v1 证书，需确认目标使用哪个。
- **变体（key 派生）**：签名 SHA1 再拼接盐/包名/版本号做 KDF；按 `hex`/`MessageDigest` 逻辑复现。
- **关联卡片**：[[mobile-android-apk-xor-string-batch-deobfuscation]]（APK 字符串 XOR 混淆）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（加固 APK 脱壳）、[[mobile-android-sqlcipher-static-key-derivation]]（静态密钥派生）。
- **边界**：重打包会改变签名，key 随之变化；若 APK 被加固/签名校验在 native 层，需脱壳/动态 hook；v2/v3 签名可能使 `signatures[0]` 与预期不同。

## 检测与防御

- **不要把签名当密钥**：签名是公开的；敏感数据应使用服务端下发/设备 Keystore 的密钥，并结合 attested 环境。
- **完整性校验**：签名校验应结合服务端 nonce/挑战、代码完整性证明（Play Integrity），不要只做本地字符串比较。
- **加固**：关键校验放 native/服务端，混淆常量；但加固不能替代密钥管理。
- **检测**：审计 `GET_SIGNATURES`、`MessageDigest("SHA1")`、XOR 解密组合；监控重打包/签名不一致的安装。
