---
id: web-generic-auth-sms-code-echo-response-arbitrary-login
title: 短信验证码在响应包/跳转 URL 中回显：任意手机号直接登录
type: scenario
domain: web
path: web/generic/auth
technique: sms-otp-response-echo-arbitrary-login
aliases:
- 验证码回显
- 短信验证码泄露
- SendSMS 返回验证码
- 任意用户登录
- OTP 回显
- sms= 参数泄露
tags:
- web
- auth
- sms
- otp
- verification-code
- account-takeover
- logic-flaw
- pii
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V72
  verified_at: '2026-11-05T16:36:12+08:00'
  notes: '已对照原文与图02-08核对：POST /Home/SendSMS 响应 Data 直接回显6位码，短信收到同码，跳转URL #/passed?sms= 亦带码，手机微信默认浏览器打开后输入该码可登录未注册手机号；卡内示例码 103910 与截图 103940 不一致，已统一修正为 103940；未本地复现'
---

## 一句话结论

登录短信接口在 HTTP 响应里直接把生成的 6 位验证码放在 `Data` 字段返回（文章为 `POST /Home/SendSMS` → `{"Success":true,"Data":"103940"}`），跳转 URL 里还会带 `#/passed?sms=103940`；攻击者只需为任意目标手机号请求一次验证码、从响应或 URL 读出该码，再提交“目标手机号 + 该码”即可登录目标账号，完全不需要持有受害者手机。

## 原理

- 短信验证码是“持有手机”这一认证因子的证明；服务端应生成随机码、与手机号/会话绑定、仅通过短信通道下发，并在校验时验证该码确实发给该手机号且未过期/未使用。
- 文章目标的 `/Home/SendSMS` 接口在 JSON 响应的 `Data` 字段返回了验证码本身（同一响应还能看到手机号 `cell`），前端拿到后用于后续登录；这等于把验证码直接交给任何能发请求的人。
- 登录跳转链路还把验证码拼进 URL fragment：`.../?code=001...&state=000#/passed?sms=103940`，浏览器历史、Referer、代理日志、截图分享都可能泄露；即使响应体不回显，URL 回显也足以利用。
- 攻击流程：输入目标手机号（无需注册/无需是该号主人）→ 请求验证码 → 读响应 `Data` 或跳转 URL 的 `sms=` → 在验证码输入页填入 → 服务端校验手机号+码并签发会话 → 以目标手机号身份登录。
- 文章在电脑端微信服务号里数字键盘无法点击，先在手机微信打开页面、输入从响应包读到的验证码完成登录证明；这说明前端交互限制不构成防护，直接调用登录接口或换端即可。
- 登录后即可访问该手机号对应的医疗业务数据（就诊人、预约、报告等），并进一步发现接口越权/三要素泄露，说明验证码回显是整条数据泄露链的入口。

## 触发条件

- 目标存在手机号 + 短信验证码登录/注册流程，验证码由服务端生成但通过响应体、响应头、跳转 URL、前端变量等方式回显。
- 登录校验只比对“手机号 + 验证码”，未校验验证码与请求会话/设备的绑定；验证码在有效期内可用。
- 攻击者能访问发送验证码接口，且接口不要求先证明持有该手机号（通常只要求手机号格式合法）。
- 没有额外的密码、人脸、设备绑定等二次校验阻断登录。

## 利用步骤

1. 打开登录页，输入一个未注册/目标手机号，点击“获取验证码”，用 Burp 拦截请求与响应。
2. 在响应中查找验证码：文章为 `POST /Home/SendSMS` → `{"Success":true,"Message":"","Data":"103940"}`；同时记录请求中的 `cell` 手机号。
3. 若响应体没有，检查跳转 URL/URL fragment（如 `#/passed?sms=103940`）、响应头、Cookie、前端 JS 变量或短信接口的 debug 字段。
4. 在验证码输入页填入读到的码并提交；若前端键盘不可用，直接用手机微信打开页面输入，或对登录接口重放 `phone + code`。
5. 登录成功后确认身份（页面显示目标手机号对应的姓名/就诊人），并测试可访问的业务功能与数据。
6. 记录请求/响应作为证据；批量测试时控制频率，避免短信轰炸告警；仅在授权范围内操作。

## PoC

```http
POST /Home/SendSMS HTTP/1.1
Host: <target>
Content-Type: application/json

{"cell":"<目标手机号>"}
```

```json
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"Success":true,"Message":"","Data":"103940"}
```

```text
# 跳转 URL 回显（文章示例）
https://<target>/home/?code=001IBJ1w3ZIS163Wz83w32je1A4IBJ1J&state=000#/passed?sms=103940
```

```http
POST /Home/Login HTTP/1.1
Host: <target>
Content-Type: application/json

{"cell":"<目标手机号>","smsCode":"103940"}
```

## 变体与关联

- 变体：验证码在响应 JSON 的 `data`、`code`、`msg`、`debug` 字段；在响应头 `X-Code`；在重定向 Location 或 URL fragment 的 `sms=`/`code=` 参数；在前端 JS 全局变量/console。
- 变体：验证码未与手机号绑定（同一码可用于其他号码）、固定万能码、验证码可枚举/爆破（4-6 位）、验证码在有效期内可重复使用。
- 变体：注册/找回密码/绑定手机等流程同样回显验证码，可组合成任意账号注册或接管。
- 边界：服务端只通过短信通道下发、验证码与手机号+会话绑定且一次性、接口有图形/行为验证码与频率限制、登录有二次校验时，本手法不成立。
- 关联：[[web-generic-auth-sms-code-multi-number-shared-arbitrary-login]]（多号码同码导致任意登录，另一类验证码绑定缺陷）、[[web-generic-auth-applicantchange-pin-sms-bypass-registration]]（短信接口参数组合绕过）、[[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]（2FA 验证码爆破与参数篡改）、[[web-generic-auth-patient-infocode-idor-pii-enumeration]]（本文登录后的三要素越权泄露）。

## 检测与防御

- 检测（测试方）：对发送验证码接口抓包，搜索响应体/响应头/URL/前端变量中的 4-6 位数字；对比手机实际收到的短信验证码是否一致；尝试用回显码登录目标手机号。
- 检测（防御方）：接口响应/日志/URL 中绝不应出现验证码；监控同一 IP/设备对大量手机号请求验证码（短信轰炸/枚举），以及验证码校验失败率异常。
- 修复：验证码只在服务端生成与存储，绑定手机号 + 会话/请求 ID，一次性使用、短有效期；响应只返回“发送成功”，不返回任何验证码字段；登录时校验绑定关系。
- 加固：短信接口加图形/行为验证码、频率与号码维度限流；对敏感登录增加设备指纹/二次校验；审计日志脱敏，避免 URL 携带敏感参数。
