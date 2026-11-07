---
id: mobile-android-param-encryption-des-md5-timewindow
title: Android 请求参数加密逆向：DES/ECB + MD5(str2+salt+时间窗) 密钥 + Base64
type: scenario
domain: mobile
path: mobile/android
technique: android-param-encryption-des-md5-timewindow
tags:
- android
- reverse
- des
- md5
- base64
- frida
- parameter-encryption
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V121
  verified_at: '2026-11-06T04:09:22+08:00'
  notes: '已对照原文及8张图核对：SecretHelper.encode/decode、getSecretKey 盐值 #F&Nfsdf*^48MG<tmli、c0.a 的 MD5 十六进制、l/500000 时间窗及 decode 回退、DES/ECB/PKCS5Padding、Base64、Frida 输出与 Python 解密 13800138000 均一致；应用无版本标记，affected_versions 已清空；PoC 未本机执行'
url: /docs/mobile/android/mobile-android-param-encryption-des-md5-timewindow/
draft: false
kb_aliases:
- SecretHelper
- getSecretKey
- DES/ECB/PKCS5Padding
- phoneNum 加密
- 时间窗
- Frida hook encode
---

## 一句话结论

App 的 `phoneNum` 由 `SecretHelper.encode(str, str2, l)` 加密：密钥是 `MD5(str2 + "#F&Nfsdf*^48MG<tmli" + l/500000)` 的前 8 个十六进制字符，算法为 DES/ECB/PKCS5Padding，结果 Base64；用同样的 `str2`、时间戳 `l` 和密文即可离线解密，时间窗失败时回退到 `(l/500000)-1`。

## 原理

- **入口**：抓包看到 `phoneNum=MfyaoRGu7RQ5b+ZhWIf2hg%3D%3D`（URL 解码后 `MfyaoRGu7RQ5b+ZhWIf2hg==`），同时请求带 `str2`（如 `getSMScode`）和时间戳 `l`。
- **定位类**：jadx 搜 `aes`/`encrypt`/`decrypt` 找到 `SecretHelper`；类里既有 `aesEncrypt/aesDecrypt`（AES/CBC/PKCS5Padding），也有真正用于参数的 `encode/decode`（DES/ECB/PKCS5Padding）。不要被 AES 方法误导。
- **密钥派生**：`getSecretKey(str, l) = c0.a(str + "#F&Nfsdf*^48MG<tmli" + l)`；`c0.a` 对拼接串做 MD5，把 digest 每个字节转两个十六进制字符；本题 Python 用 `hashlib.md5(...).hexdigest()[:8]`（小写）作为 8 字节 DES key。若失败可尝试大写/不同大小写表。
- **时间窗**：`encode/decode` 里 `Long.valueOf(l / 500000)`，即毫秒时间戳整除 500000；`decode` 先试当前窗口，抛异常再试 `(l/500000)-1`，覆盖跨窗口边界。
- **DES 参数**：`DESKeySpec(key.getBytes())` → `SecretKeyFactory.getInstance("DES").generateSecret(...)`；`Cipher.getInstance("DES/ECB/PKCS5Padding")`；`init(1/2, secretKey, SecureRandom)`；加密后 `Base64.encodeBase64`，解密前 `Base64.decodeBase64`。
- **验证**：Frida Hook `SecretHelper.encode/decode` 的 `(String, String, Long)` 重载，打印 `str/str2/l/result`，与抓包 `phoneNum` 对比一致；Python 用 `str2=getSMScode`、`l=1759023827018`、密文解出 `13800138000`。

## 触发条件

- App 对请求参数做客户端加密，Burp 只能看到 Base64/hex 密文。
- APK 未加固，可用 jadx 搜索 `aes`/`encrypt`/`decrypt`/`SecretHelper`。
- 加密参数旁边带业务标识 `str2` 和时间戳 `l`，或可从请求中恢复。
- 能运行 Frida/动态调试验证 key 和明文。

## 利用步骤

1. 抓包记录密文字段、`str2`、时间戳 `l`；对密文做 URL 解码/Base64 解码。
2. jadx 搜索 `aes`/`encrypt`/`decrypt`，定位 `SecretHelper`；区分 AES 方法与实际 `encode/decode`。
3. 跟进 `getSecretKey` → `c0.a`，确认 MD5、十六进制大小写、取前 8 位、盐值。
4. 确认 `l/500000` 时间窗和 `decode` 的回退窗口；确认 DES 模式/填充/IV（本题 ECB 无 IV）。
5. 用 Frida Hook `encode/decode` 重载，打印输入输出，验证 key/明文。
6. 用 Python 复现：`key=md5(str2+salt+window)[:8]`，DES-ECB 解密 Base64 密文；失败时换窗口/大小写。

## PoC

Frida Hook：

```javascript
Java.perform(function () {
  const SecretHelper = Java.use("cn.passiontec.dxs.helper.SecretHelper");
  const encode = SecretHelper["encode"].overload("java.lang.String", "java.lang.String", "java.lang.Long");
  encode.implementation = function (str, str2, l) {
    const result = encode.call(this, str, str2, l);
    console.log("[ENCODE]", str, str2, l, "=>", result);
    return result;
  };
});
```

Python 解密：

```python
import base64
import hashlib
from Crypto.Cipher import DES

def get_secret_key(s, t):
    raw = f"{s}#F&Nfsdf*^48MG<tmli{t}"
    return hashlib.md5(raw.encode()).hexdigest()[:8]  # 8 字节 DES key

str2 = "getSMScode"
l = 1759023827018
cipher_b64 = "MfyaoRGu7RQ5b+ZhWIf2hg=="
key = get_secret_key(str2, l // 500000)

des = DES.new(key.encode(), DES.MODE_ECB)
plain = des.decrypt(base64.b64decode(cipher_b64)).decode("utf-8")
print(plain)  # 13800138000
```

## 变体与关联

- **算法变体**：DES/ECB、DES/CBC（需要 IV）、AES/CBC/PKCS5Padding（同类里也有 `aesEncrypt/aesDecrypt`）、3DES；先确认 `Cipher.getInstance` 和 `init` 参数。
- **密钥变体**：MD5 前 8/16 位、大写/小写十六进制、盐值不同、时间窗除数不同、时间戳单位秒/毫秒。
- **动态验证变体**：Frida Hook `encode/decode`、`getSecretKey`、`Cipher.doFinal`；也可直接调用类方法加密已知明文对比。
- **关联卡片**：[[mobile-android-apk-xor-string-batch-deobfuscation]]（字符串/算法定位）、[[mobile-android-ssl-pinning-bypass-cert-frida]]（抓包环境）、[[ctf-reverse-apk-jni-username-xtea-hex-sse-compare]]（JNI 参数加密）。
- **边界**：若盐/密钥在 native 层或服务端动态下发、或使用随机 IV 且 IV 不随包传输，需要额外 Hook/逆向；时间窗跨边界时用回退窗口。

## 检测与防御

- **防御**：客户端加密不能替代 TLS/证书 pinning；密钥/盐不要硬编码；使用服务端下发短期密钥、随机 IV、AEAD；对重放做 nonce/时间窗校验。
- **检测信号**：请求参数为 Base64/hex 且旁边带时间戳/业务标识；APK 中有 `SecretHelper`/`getSecretKey`/MD5+DES 组合；Frida Hook 可打印明文。
- **测试建议**：先 Hook 确认 key 派生，再写离线脚本；注意 URL 编码、Base64 填充、时间窗回退。
