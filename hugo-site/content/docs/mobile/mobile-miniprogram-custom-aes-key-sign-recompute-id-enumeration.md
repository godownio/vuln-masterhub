---
id: mobile-miniprogram-custom-aes-key-sign-recompute-id-enumeration
title: 小程序 AES-ECB 密钥由双常量自派生 + MD5(json+timestamp) 签名重算 + 顺序 id 遍历
type: scenario
domain: mobile
path: mobile
technique: miniprogram-custom-aes-key-sign-recompute-id-enumeration
tags:
- mobile
- miniprogram
- reverse
- aes
- ecb
- md5
- signature
- idor
- enumeration
- pii
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V286
  verified_at: '2026-11-08T04:56:53+08:00'
  notes: 已对照原文与5张图核对：抓包含 encryptData/sign(md5)/timestamp、JS 中 .slice(0,16).toString('hex') 派生 key、AES.encrypt(..., {mode:ECB,padding:Pkcs7})、base64 后 +→- /→_ 替换、解密输出 '"phone":"133..."'、sign=md5(json数据+时间戳)、id 非随机可遍历均与卡片一致；卡面对 key 长度(Utf8.parse vs Hex.parse)的不确定性已如实标注，confidence=medium 合理。未验证点：原文打码未给出完整常量/派生算法，未复跑解密/遍历脚本。dedup 除自身外 top related 均为纯签名伪造类小程序卡，不含 AES body 加密+密钥派生+id 遍历组合，非同一链；dup-scan pair 187 对方为前端 const.js 管理员账号+找回密码回显手机号，机制不同，保留两张。frontmatter 无 sources/source_url。
url: /docs/mobile/mobile-miniprogram-custom-aes-key-sign-recompute-id-enumeration/
draft: false
kb_aliases:
- 小程序加解密
- 小程序 AES-ECB
- 双常量派生 AES key
- MD5(json+timestamp) 签名
- sign 重算
- id 遍历信息泄露
- wxapkg 反编译
- URL-safe Base64
---

## 一句话结论

小程序把请求/响应体用 AES-ECB/PKCS7 加密，密钥由两个常量经自实现简单算法混淆后取 hex 前 16 位得到，密文再用 URL-safe Base64 传输；签名是 `MD5(JSON 数据 + 时间戳)`，没有服务端密钥。反编译小程序还原密钥派生与签名算法后，攻击者可以重新加密任意请求、重算签名，并遍历 `/xxid_info` 的顺序 id 批量获取他人手机号等敏感信息。

## 原理

- **前端加密不是安全边界**：小程序包（wxapkg）可被解包，`app-service.js` 中的加密函数、常量与算法对攻击者可见；密钥由客户端计算，所以客户端一定持有密钥。
- **密钥派生**：代码中定义两个常量，用一个自实现的简单算法混淆，取结果 hex 字符串的前 16 位作为 AES key。这里的“16 位”通常指 16 个十六进制字符；若按 `Utf8.parse` 作为字符串密钥，16 个 ASCII 字符正好 16 字节（AES-128）；若代码用 `Hex.parse`，则 16 个 hex 字符只有 8 字节，需以实际运行结果/解密工具显示的 key 长度为准。攻击者照着 JS 复现即可，不需要破解 AES。
- **ECB 模式确定性**：`AES.encrypt(data, key, {mode: ECB, padding: Pkcs7})` 对相同明文/密钥产生相同密文，模式选择不构成额外保护；密文 Base64 后把 `+` 替换为 `-`、`/` 替换为 `_`，解密前需还原为标准 Base64。
- **签名无秘密**：`sign = md5(json数据 + 时间戳)`，没有 HMAC/服务端盐值/nonce；攻击者修改 id 后，用新 JSON + 当前时间戳重新计算 MD5 即可得到合法签名，所谓“一次性校验”只防住了不会重算的人。
- **真正的授权缺陷**：`/xxid_info` 按请求中的 id 返回用户信息，id 不是随机值而是顺序/可预测；服务端没有校验当前登录用户是否有权访问该 id，因此遍历 id 就能拿到他人信息。
- **批量利用**：脚本对每个 id 构造 `{"id": n}` → AES 加密 → URL-safe Base64 → 重算 sign/timestamp → 发送 → 解密响应 → 提取手机号等字段；文章截图显示解密后的响应包含 `"phone":"133..."`。

## 触发条件

- 目标为微信/其它小程序，请求或响应体有加密字段（如 `encryptData`）、签名与时间戳。
- 加密算法、密钥派生逻辑、签名算法可从 wxapkg/`app-service.js` 或运行时还原。
- 签名不含服务端密钥/HMAC/nonce，或时间戳可自由设置。
- 业务接口按顺序/可预测 id 查询用户信息，未校验对象归属。
- 接口没有严格的频率限制/风控，允许批量请求。

## 利用步骤

1. 抓取小程序请求与响应，记录加密字段、`sign`、`timestamp` 与接口路径（案例为 `/xxid_info`）。
2. 解包小程序（如 wxappUnpacker），在 `app-service.js` 中定位 AES 加密函数、两个常量、混淆算法、`slice(0,16).toString("hex")`、ECB/PKCS7 与 Base64 替换逻辑。
3. 按 JS 逻辑复现密钥派生，验证能解密自己的请求/响应。
4. 还原签名：`sign = md5(json数据 + 时间戳)`，确认服务端接受用新时间戳重算的签名。
5. 构造 `{"id": <目标 id>}`，加密、编码、重算 sign/timestamp 后发送；解密响应确认返回目标用户信息。
6. 遍历 id（控制频率与范围），批量解密并提取手机号等 PII；在授权范围内记录证据，不下载/扩散无关数据。

## PoC

```javascript
// 小程序 JS 中的加密逻辑（示意，按目标实际代码调整）
const keyStr = obfuscate(CONST1, CONST2).toString("hex").slice(0, 16);
const key = CryptoJS.enc.Utf8.parse(keyStr); // 16 个 ASCII 字符 = 16 字节；若目标用 Hex.parse 则按实际调整
const cipher = CryptoJS.AES.encrypt(JSON.stringify({id: targetId}), key, {
  mode: CryptoJS.mode.ECB,
  padding: CryptoJS.pad.Pkcs7
}).toString();
const encryptData = cipher.replace(/\+/g, "-").replace(/\//g, "_");
const sign = md5(JSON.stringify({id: targetId}) + Date.now());
```

```python
# 解密侧（pycryptodome 示意）
import base64, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt(enc):
    std = enc.replace('-', '+').replace('_', '/')
    raw = base64.b64decode(std + '=' * (-len(std) % 4))
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(raw), 16)

def sign_for(data_json, ts):
    return hashlib.md5((data_json + str(ts)).encode()).hexdigest()
```

## 变体与关联

- **前端 AES-ECB 硬编码密钥 + 学号遍历**：Web 端的同类链，密钥直接硬编码；参见 [[web-generic-auth-frontend-aes-ecb-hardcoded-key-student-id-pii-enumeration]]。
- **小程序国密 SM2/SM3/SM4 协议**：更复杂的国密封装与 Burp 透明加解密；参见 [[mobile-miniprogram-sm-crypto-protocol-burp-transparent]]。
- **动态密钥加密接口越权**：密钥每请求动态生成，需在浏览器断点固定/复用页面函数；参见 [[code-analysis-reverse-dynamic-key-encrypted-api-idor]]。
- **请求/响应双层加密自动化**：XHR 断点、扣 JS、PyExecJS 自动化；参见 [[code-analysis-reverse-frontend-request-response-encryption-automation]]。
- **签名可重算**：无服务端密钥的 MD5 签名可被任意重算；参见 [[web-generic-auth-nested-md5-sign-reverse-forgery]]、[[mobile-android-c2-api-md5-salt-signature-replay]]。

## 检测与防御

- **服务端授权**：按当前登录用户校验目标 id 的归属/角色/数据范围，不能信任客户端提交的 id；对查询接口做对象级授权。
- **签名密钥服务端化**：使用 HMAC-SHA256 + 服务端密钥，签名覆盖方法、路径、body、时间戳与 nonce；服务端校验时间窗口与 nonce 一次性，拒绝重放。
- **不要依赖前端加密**：前端 AES 只能防止明文抓包，不能替代授权；ECB 模式应改为带随机 IV 的 AEAD（GCM）或至少 CBC+HMAC。
- **接口防护**：按账号/IP/设备做频率限制、批量查询阈值与异常检测；敏感字段（手机号、身份证）按需脱敏返回。
- 检测：同一账号短时间遍历连续 id、签名时间戳异常重复/跳跃、请求体长度固定但 id 递增、响应解密后含大量不同用户 PII。
