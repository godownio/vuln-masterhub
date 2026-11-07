---
id: mobile-harmony-hap-hardcoded-admin-token-sm4-flag
title: HAP 静态提取硬编码管理员哈希：SHA256 token 派生 + SM4-ECB 解密 flag
type: scenario
domain: mobile
path: mobile/harmony
technique: hap-hardcoded-admin-hash-sha256-token-sm4-ecb
tags:
- harmonyos
- mobile
- reverse
- hap
- arkts
- sha256
- token
- sm4
- ecb
- hardcoded-credential
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:19:54+08:00'
  notes: 已对照原文与图02/10/12核对：硬编码 admin + af0d3a...3869、TOKEN_SALT=hmos_ctf_2026、currentToken=fb809f9d...b518、二次 SHA256 token|admin|HMOS_CTF_2026 取前 32 hex=51a8f50d...afbe、48 字节密文、SM4_128|ECB|PKCS7、16 字节 key 校验、flag=_webview_jsbridge_trust_broken_2026_ 均与原文一致；JSBridge 仅作为设计风险记录，未给外部利用链。PoC 未本机复跑；原文未标注组件版本。
url: /docs/mobile/harmony/mobile-harmony-hap-hardcoded-admin-token-sm4-flag/
draft: false
kb_aliases:
- Bridge.hap
- admin password hash
- TOKEN_SALT hmos_ctf_2026
- HMOS_CTF_2026
- SM4_128|ECB|PKCS7
- currentToken
- 鸿蒙 CTF 逆向
---

## 一句话结论

从 HarmonyOS `modules.abc` 中可静态提取硬编码的 admin 密码哈希与 `TOKEN_SALT`，按 `currentToken = SHA256(username + passwordHash + salt)` 复现 token，再按 `key = SHA256(currentToken + "|admin|HMOS_CTF_2026")[:32]` 派生 16 字节 SM4 密钥，用 `SM4_128|ECB|PKCS7` 解密硬编码密文即得 flag；整个过程不需要运行 App。

## 原理

- **硬编码凭据**：`DatabaseUtil` 初始化数据库时执行 `INSERT OR IGNORE INTO user (username, password) VALUES ('admin', '<sha256>')`，用户名 `admin`、密码哈希 `af0d3a...3869` 直接出现在字节码字符串常量中。
- **Token 派生**：`buildToken(username, passwordHash)` 等价于 `sha256Hex(username + passwordHash + TOKEN_SALT)`，`TOKEN_SALT = "hmos_ctf_2026"`；`generateTokenByUsername('admin')` 查询数据库后调用它。代入得 `currentToken = fb809f9d941bb2dc8034978ee02cd35b688c2ba93be23b6d25d91fa7ef5fb518`。
- **二次哈希派生 SM4 key**：Home 页 `decryptLocalFlag(token)` 先校验 token 等于 `generateTokenByUsername('admin')`，再计算 `sha256Hex(token + "|" + "admin" + "|" + "HMOS_CTF_2026")`，取前 32 个十六进制字符（16 字节）作为 SM4 key。
- **SM4-ECB 解密**：`FlagUtil` 中硬编码 `LOCAL_FLAG_CIPHER_HEX`（48 字节、3 个分组），`sm4Decrypt` 使用 `cryptoFramework.createCipher("SM4_128|ECB|PKCS7")`，`genSm4KeyByData` 要求 key 长度恰好 16 字节；解密后 PKCS7 去填充、UTF-8 解码即 flag。
- **为什么可行**：客户端把“认证凭据 + 派生盐 + 密文”全部打包进 HAP，密钥派生完全确定性；攻击者只需静态提取常量并复现 SHA256/SM4，不需要真实登录或动态调试。
- **JSBridge 风险**：Home 页通过 `javaScriptProxy` 把 `ctfBridge` 的 `saveUser`/`refresh`/`getCurrentUser`/`getCurrentToken` 暴露给 WebView，并通过 `runJavaScript` 把 `flagText` 注入页面；若 WebView 加载不可信页面或存在 XSS，token/flag 可能被前端脚本读取（本题未给出外部 URL 入口，属于设计风险）。

## 触发条件

- 目标为 HarmonyOS HAP/APP，核心逻辑在 ArkTS/ABC 中且未加壳/未重度混淆。
- 管理员凭据、盐、密文以字符串常量硬编码在 `modules.abc`（或可静态恢复）。
- Token 与 SM4 密钥派生链是确定性的 SHA256 拼接，盐值可从代码中提取。
- 攻击者能解包 HAP、反编译 ABC、实现或调用 SM4-ECB 解密。

## 利用步骤

1. 解包 HAP，反编译 `ets/modules.abc`，定位 `DatabaseUtil`/`FlagUtil`/`Home`。
2. 从 `DatabaseUtil` 的 INSERT 语句提取 `admin` 与 64 位密码哈希；从 `func_main_0` 提取 `TOKEN_SALT`（如 `hmos_ctf_2026`）。
3. 计算 `currentToken = SHA256(admin + passwordHash + TOKEN_SALT)`。
4. 从 `Home.decryptLocalFlag` 提取二次哈希格式（如 `token + "|admin|HMOS_CTF_2026"`），计算 `keyHex = SHA256(...)[:32]`，转 16 字节 key。
5. 从 `FlagUtil` 提取 `LOCAL_FLAG_CIPHER_HEX`，用 SM4-ECB-PKCS7 解密，去填充后 UTF-8 解码。
6. 若密文/哈希提取失败，用正则从 `modules.abc` 的字符串常量中匹配 64 位十六进制哈希与更长的十六进制密文。

## PoC

```python
import hashlib

ADMIN_USER = "admin"
PASSWORD_HASH = "af0d3a523b93a558a63d07929efd58f4a1fad1b34348bdb06e547b1151863869"
TOKEN_SALT = "hmos_ctf_2026"
HOME_SALT = "HMOS_CTF_2026"
CIPHER_HEX = "5a52339fbdb9b11b330ed4ffd6f06b453e0d3fb96a624a71b16124065c2d9e3362fa1d5941b0995e559002b759cf91a9"

token = hashlib.sha256((ADMIN_USER + PASSWORD_HASH + TOKEN_SALT).encode()).hexdigest()
key_hex = hashlib.sha256((token + "|admin|" + HOME_SALT).encode()).hexdigest()[:32]
print("token =", token)
print("key   =", key_hex)

# SM4-ECB-PKCS7 解密（可用 gmssl / 手写 SM4）
# from gmssl.sm4 import CryptSM4, SM4_DECRYPT
# sm4 = CryptSM4(); sm4.set_key(bytes.fromhex(key_hex), SM4_DECRYPT)
# pt = sm4.crypt_ecb(bytes.fromhex(CIPHER_HEX))
# pt = pt[:-pt[-1]].decode()
```

```text
# 例：token = fb809f9d941bb2dc8034978ee02cd35b688c2ba93be23b6d25d91fa7ef5fb518
#     key   = 51a8f50d751a48550f90b3c49439afbe
#     flag  = flag{_webview_jsbridge_trust_broken_2026_}
```

## 变体与关联

- 盐/格式变体：`TOKEN_SALT`、`HOME_SALT`、分隔符 `|` 可换成其他常量；从 `func_main_0` 与 `decryptLocalFlag` 精确提取。
- 算法变体：SM4-ECB 可换 SM4-CBC/CTR（需要 IV）、AES-GCM、国密 SM2/SM3；密钥派生可换成 PBKDF2/HKDF。
- 保护变体：字符串加密/ABC 混淆/加壳时，需先恢复常量；见 [[mobile-harmony-arkts-napi-obfuscated-constants-sm4-vm-flag]]、[[mobile-harmony-hap-arkts-native-sbox-affine-unicorn]]。
- 关联：[[mobile-harmony-hap-abc-reverse-sourcemaps-workflow]]（HAP/ABC 逆向流程）、[[mobile-android-webview-jsbridge-arbitrary-origin-credential-theft]]（WebView/JSBridge 信任边界）。

## 检测与防御

- 检测：HAP 的 `modules.abc` 字符串常量中出现 64 位十六进制哈希、长十六进制密文、`TOKEN_SALT`/`SM4_128` 等关键字；sourceMaps 未剥离；客户端存在硬编码管理员凭据。
- 防御：不要在客户端硬编码管理员凭据、盐、密钥或密文；认证与解密逻辑放服务端；使用服务端下发的短期令牌与安全存储。
- 加固：发布构建剥离 sourceMaps、启用 ABC 混淆/字符串加密、加壳；WebView 做域名白名单与 JSBridge 鉴权，不向不可信页面暴露 token/flag。
