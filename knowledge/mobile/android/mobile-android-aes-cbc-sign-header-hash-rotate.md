---
id: mobile-android-aes-cbc-sign-header-hash-rotate
title: Android API sign 逆向：SHA-256 hex 重排 + AES-CBC 生成请求头签名
type: scenario
domain: mobile
path: mobile/android
technique: android-aes-cbc-sign-header
aliases:
- 校园 App sign 逆向
- AES-CBC sign
- SHA-256 hex 重排
- 请求头 sign 伪造
- gh.a.b 签名
tags:
- android
- reverse
- sign
- aes-cbc
- sha256
- api-protocol
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:22:19+08:00'
  notes: 已对照原文与截图核对：gh.a.b 的 SHA-256 hex 首8/末8重排、gh.a.a 的 AES/CBC/PKCS5Padding+Base64、IV=01234ABCDEF56789、key 选择 (x7.d.b()==9||11)?F44B0282BEA83557:huachenjie、c() 补零到32字节、请求体 JSON→hash→AES→sign 头均一致。未验证点：未复跑 Python 签名脚本；第二个 key 的资源图片派生细节原文未完全展开。
---

## 一句话结论

App 的 `sign` 请求头不是简单哈希，而是“先对请求 JSON 做 SHA-256，把十六进制串的首 8 位与末 8 位交换，再用 AES-128-CBC（固定 key/IV）加密该 hash 字符串”；逆向出 `gh.a.b`/`gh.a.c`/`d0.h` 与密钥选择逻辑后，即可在 Python 中复现签名并伪造/重放请求。

## 原理

- 抓包可见请求带 `sign` 字段，响应体加密；在 jadx 中搜索 `addHeader`/`sign`，定位到 `d0.h(String, RequestBody)` 之类的封装。
- 哈希函数 `gh.a.b(str, "SHA-256")`：对输入做 SHA-256，转 hex；若长度 ≥16，则把最后 8 个字符移到前面、前 8 个字符移到末尾，形成重排后的 hash 字符串。
- 签名函数 `gh.a.a(str, str2)`：`AES/CBC/PKCS5Padding`，key 由 `c(key_str)` 生成——把字符串按 UTF-8 取前 32 字节、不足补 `\0` 到 32 字节；IV 固定为 `01234ABCDEF56789`；对 hash 字符串加密后 Base64。
- 密钥选择：`(x7.d.b() == 9 || x7.d.b() == 11) ? "F44B0282BEA83557" : "huachenjie"`；`x7.d.b()` 是运行环境判断，初始值 9，因此常用固定 key `F44B0282BEA83557`。另有第二个 key 由资源图片计算/固定值提供，用于数据加密。
- 请求体通常先 `HashMap` → `JSON.toJSONString` → hash → AES 加密 → 放入 `sign` 头；响应体用同一套 key/IV 解密。
- 根因是客户端持有对称密钥与算法，攻击者可通过逆向完全复现签名，服务端无法区分“App 生成”与“脚本生成”。

## 触发条件

- 拿到 APK，能脱壳/反编译（易盾等壳可用在线/动态脱壳）。
- 请求/响应使用固定 key 的对称加密或可复现的哈希签名。
- 能定位 `addHeader`/`sign`/AES 工具类与密钥选择逻辑。
- 服务端未绑定设备指纹/时间戳/一次性 nonce，或这些字段也可复现。

## 利用步骤

1. 抓包确认 `sign` 头与加密响应；记录请求 JSON 字段顺序（签名通常对规范化 JSON 计算）。
2. 脱壳后 jadx 搜索 `addHeader`、`sign`、`AES`、`CBC`、`SHA-256`，定位签名封装与工具类。
3. 跟踪密钥选择（环境判断、资源图片派生、BuildConfig），记录 key/IV。
4. 用 Python 复现：SHA-256 → hex 重排 → AES-CBC/PKCS7 → Base64，放入 `sign` 头。
5. 发送请求验证；若服务端校验时间戳/nonce，按同样逻辑生成。

## PoC

```python
import base64, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

IV = b"01234ABCDEF56789"
key_str = "F44B0282BEA83557"

def c(s):
    b = s.encode()
    return (b + b"\x00" * 32)[:32]

def obfuscated_hash(s, algo="sha256"):
    h = hashlib.new(algo); h.update(s.encode())
    x = h.hexdigest()
    return x if len(x) < 16 else x[-8:] + x[8:-8] + x[:8]

def encrypt_aes(plain):
    cipher = AES.new(c(key_str), AES.MODE_CBC, IV)
    return base64.b64encode(cipher.encrypt(pad(plain.encode(), 16))).decode()

def calculate_sign(data):
    return encrypt_aes(obfuscated_hash(data))
```

## 变体与关联

- 哈希可换成 MD5/SHA1/HMAC；重排规则可换成字符反转、分段交换、加盐。
- 密钥可能来自 native so、资源图片、设备信息派生；需动态 hook 或算法还原。
- 关联：[[mobile-android-c2-api-md5-salt-signature-replay]]（MD5 salt 签名重放）、[[mobile-android-okhttp-addheader-stack-native-sign-locate]]（定位 addHeader/native 签名）。

## 检测与防御

- 使用 HMAC/非对称签名，密钥放服务端或 TEE；不要把对称密钥硬编码在 APK。
- 加入时间戳、一次性 nonce、设备绑定与服务端风控；对重放/异常频率做检测。
- 检测：同一账号短时间大量请求、sign 正确但设备指纹/行为异常。
