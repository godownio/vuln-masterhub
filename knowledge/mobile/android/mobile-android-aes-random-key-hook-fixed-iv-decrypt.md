---
id: mobile-android-aes-random-key-hook-fixed-iv-decrypt
title: Android 请求/响应 AES 解密：hook CryptoHelper.getKey 固定随机 key + 固定 IV 的 CBC/PKCS7+Base64
type: scenario
domain: mobile
path: mobile/android
technique: android-aes-random-key-hook-fixed-iv-decrypt
aliases:
- CryptoHelper getKey hook
- Android AES 抓包解密
- 随机 key 请求体传递
- 固定 IV a396202596eacb41
- AES/CBC/PKCS7Padding
- 登录 key=iv=MD5(salt+timestamp)
tags:
- android
- aes
- cbc
- pkcs7
- frida
- hook
- traffic-decrypt
- okhttp
- cryptohelper
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V128
  verified_at: '2026-11-06T04:07:42+08:00'
  notes: 已对照原文核对：cryptoBody 的 EncryptUtils.encryptAES(AES/CBC/PKCS7Padding)+base64、固定 IV a396202596eacb41、请求体 {data,key} 随机 key 传递、hook getKey 返回 45240993c26bd4-1、/login key=iv=MD5(e701c10fc81cf92ec185b9cebe089ce1#@^@#+时间戳) 均与原文一致；图为 session_key_token/session_key_user XML 与验证码，佐证响应解密内容。未验证点：未在真机复跑 hook 与解密；响应与请求同 key/iv 为原文代码推断；单样本。frontmatter 无 sources/source_url。
---

## 一句话结论

App 的请求/响应体是 `Base64(AES/CBC/PKCS7(明文, 随机 key, 固定 IV))`，随机 key 放在请求 JSON 的 `key` 字段随包传输；hook `CryptoHelper.getKey()` 让它返回固定值，即可用固定 key + 固定 IV 在 CyberChef/Python 中批量解密请求与响应。登录接口另有 `key=iv=MD5(salt + timestamp)` 的派生，需要单独处理。

## 原理

- **加密实现**：`cryptoBody(str, key)` 调用 `EncryptUtils.encryptAES(str.getBytes(), key.getBytes(), "AES/CBC/PKCS7Padding", iv.getBytes())`，再 `base64Encode2String`；`iv` 是 `CryptoHelper` 中的固定字符串（样本 `a396202596eacb41`，16 字节）。
- **随机 key 的传递**：`CryptoHelper.getKey()` 每次生成随机 AES key；请求体是 `{"data":"<base64 密文>","key":"<key>"}`，服务端用同一 key 解密并返回同样格式的响应。因为 key 与密文同包传输，抓包者只要拿到 key 就能解密，加密只防肉眼/简单代理。
- **hook 固定 key**：Frida hook `CryptoHelper.getKey`，返回固定 16 字节（样本 `45240993c26bd4-1`），后续所有请求/响应都用该 key；抓包后用固定 key + 固定 IV 解密，不需要每次从请求体提取 key。
- **响应解密**：`SecurityDataInterceptor` 在 `chain.proceed` 后构造 `HResponse`，设置同一个 `aesKey`，对响应体做解密/校验；请求与响应使用同一 key/iv/模式。
- **登录特殊派生**：`/login` 请求的 key 与 iv 都是 `MD5("e701c10fc81cf92ec185b9cebe089ce1#@^@#" + 该请求的时间戳)`；hook 时间戳为固定值后，key/iv 可复现。原文发现该登录包不含有效信息，重点转向 `/captcha/getCaptchaCode` + `/startup` 获取 `X-Auth-Token`。
- **为什么可行**：对称加密的 key 必须交给客户端，客户端又能被 hook/调试；没有白盒或服务端密钥协商时，抓包 + 动态 hook 即可还原明文。

## 触发条件

- App 使用 OkHttp/Retrofit，请求/响应体为 base64 的 AES 密文，JSON 中带 `key` 字段或等价密钥材料。
- 加密实现可在 Java/Kotlin 层 hook（`CryptoHelper`/`EncryptUtils`/`cipher.doFinal`），或有固定 IV/模式可复刻。
- 有 Frida/可调试环境；SSL Pinning 已绕过或未启用。
- 登录接口的 key 派生只依赖固定 salt + 时间戳，时间戳可 hook/固定。

## 利用步骤

1. 抓包确认请求/响应结构：`{"data":"...","key":"..."}`，`Content-Type: application/json`；记录 `X-Client-Timestamp` 等头。
2. 在 jadx 中搜索 `AES`、`CBC`、`PKCS7`、`cryptoBody`、`EncryptUtils`、`getKey`，定位加密类与 IV。
3. Frida hook `CryptoHelper.getKey` 返回固定 key；或 hook `cipher.doFinal`/`EncryptUtils.encryptAES` 打印 key/iv/mode。
4. 用固定 key + 固定 IV 在 CyberChef（AES Decrypt, CBC, key/iv UTF8, input base64）或 Python 解密请求/响应。
5. 对登录接口单独 hook 时间戳/`getKey`，按 `MD5(salt + timestamp)` 复现 key=iv；确认该包是否含有效信息。
6. 解密响应，提取用户信息、`X-Auth-Token`、配额字段，继续分析业务逻辑。

## PoC

```javascript
// Frida：固定随机 key
var CryptoHelper = Java.use("com.seven.movie.net.global.CryptoHelper");
CryptoHelper["getKey"].implementation = function () {
    var ret = this.getKey();
    console.log("[getKey] original = " + ret);
    return "45240993c26bd4-1";   // 16 字节固定 key
};
```

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt(b64_data: str, key: bytes, iv: bytes) -> bytes:
    ct = base64.b64decode(b64_data)
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    return unpad(pt, 16)

# 样本：key=b"45240993c26bd4-1"，iv=b"a396202596eacb41"
# plain = decrypt(body_json["data"], b"45240993c26bd4-1", b"a396202596eacb41")
```

登录特殊 key/iv：

```python
import hashlib
salt = "e701c10fc81cf92ec185b9cebe089ce1#@^@#"
ts = 1783512636  # hook 成固定时间戳
key = iv = hashlib.md5((salt + str(ts)).encode()).digest()
```

## 变体与关联

- **密钥传递变体**：key 在请求体 `key` 字段、请求头、URL 参数、RSA 加密后传输；先定位 key 的来源再解密。
- **算法变体**：AES-CBC/ECB/GCM、3DES、SM4；IV 固定/随机/随密文传输；padding PKCS7/Zero。
- **密钥派生变体**：`MD5(salt+timestamp)`、`SHA256(deviceId+nonce)`、服务端下发临时 key；hook 派生函数或固定时间戳。
- **白盒/加固变体**：native/白盒 AES 需 dump 表或动态 hook `doFinal`；参考关联卡。
- **关联卡片**：[[mobile-android-okhttp-addheader-stack-native-sign-locate]]（OkHttp 头/签名定位）、[[mobile-android-ssl-pinning-bypass-cert-frida]]（抓包绕过）、[[mobile-android-sqlcipher-static-key-derivation]]（本地加密数据）。
- **边界**：key 由服务端 RSA/ECDH 协商且客户端不落明文、或使用白盒密码时，简单 hook 可能拿不到；需要动态插桩/内存 dump。

## 检测与防御

- **检测特征**：请求/响应 JSON 含 `data`/`key` 双字段、base64 高熵；Java 层出现 `AES/CBC/PKCS7Padding`、`EncryptUtils`、`CryptoHelper`；固定 IV 常量。
- **修复**：不要把对称 key 与密文同包传输；使用 TLS + 证书固定保护传输；敏感数据用服务端密钥/硬件 Keystore；客户端加密不能替代传输层安全。
- **分析建议**：先 hook `getKey`/`doFinal` 拿 key/iv/mode，再离线解密；对登录等特殊接口单独看 key 派生。
