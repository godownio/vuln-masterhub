---
id: web-generic-auth-sms-code-empty-field-arbitrary-register-login
title: 短信验证码字段置空绕过校验：注册/登录同接口按手机号签发 token，任意用户注册与接管
type: scenario
domain: web
path: web/generic/auth
technique: sms-code-empty-field-register-login-bypass
tags:
- web
- auth
- sms
- captcha
- logic
- registration
- account-takeover
- token
- empty-value
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V241
  verified_at: '2026-11-07T13:10:31+08:00'
  notes: 已对照原文与12张图核对；空 openId/password 签发 token 与个人信息回显成立；服务端内部校验逻辑属黑盒推断，PoC 未复跑。
url: /docs/web/generic/auth/web-generic-auth-sms-code-empty-field-arbitrary-register-login/
draft: false
kb_aliases:
- 验证码置空绕过
- 空验证码登录
- 注册登录同一接口
- 任意用户注册
- 任意用户登录
- openId 置空
- SMS code empty bypass
---

## 一句话结论

当注册与登录共用 `/app/open/sms/registerAndLogin` 这类接口，且服务端对承载短信验证码/初始口令的 `openId`、`password` 字段只做非空判断或直接跳过校验时，攻击者把验证码字段置空、把 `username` 改成任意手机号，服务端就会按该号码签发 token；未注册号码被自动注册，已注册号码直接登录，形成任意用户注册与账户接管。

## 原理

- **注册/登录同接口**：该案例的 `/xjky-server/xjky-biz-server/app/open/sms/registerAndLogin` 同时承担注册和登录；服务端用 `username`（手机号）+ `tenantId` 定位用户，用 `openId`/`password` 承载短信验证码/初始口令。未注册的手机号会被自动创建账户，已注册的手机号则直接登录。
- **空值跳过校验**：服务端校验逻辑对验证码字段使用“非空才校验”或“空值视为未提交”的分支，导致空字符串 `""` 不进入比对逻辑；只要 `username` 与 `tenantId` 合法，就继续签发 `access_token`/`refresh_token`。案例中把 `openId`、`password` 都置空、`username` 改为目标手机号，仍返回 `code:10000` 和完整 token。
- **为什么能接管**：token 的 `login_id` 形如 `extend_<phone>`、`user_id` 对应该手机号用户；拿着该 token 请求个人信息接口，回显的 `loginId` 正是目标号码，说明服务端已把会话绑定到目标账户，而不是攻击者自己的账户。
- **自动注册放大**：因为登录路径对不存在的手机号会自动注册，攻击者无需短信验证即可批量创建任意手机号账户；对已注册号码则直接登录，形成“任意用户注册 + 任意用户登录”两个危害。
- **响应篡改（案例补充）**：文章还在登录口拦截响应包，把返回的 token 替换为先前为受害者号码生成的 token，客户端随后进入受害者个人信息页。这反映客户端信任登录响应中的 token；但根因仍是服务端空验证码签发 token，替换响应只是交付方式。

## 触发条件

- 注册与登录复用同一接口，接口可按 `username`（手机号）+ `tenantId` 签发 token。
- 验证码/初始口令字段（案例为 `openId`、`password`）允许为空、缺失、`null`、空白或特殊值，且服务端在空值时跳过校验。
- 验证码未与手机号/租户/业务场景强绑定，或校验失败分支可被空值绕过。
- 接口无需登录即可访问；`tenantId` 可从注册页、前端 JS、历史请求或响应中获取。
- 没有额外的设备绑定/风控/二次验证阻止新设备直接使用 token。

## 利用步骤

1. 正常走一次注册/登录，抓取 `registerAndLogin` 请求，记录 `username`、`tenantId`、`openId`、`password` 等字段。
2. 把 `openId`、`password` 置空（或删除字段/传 `null`/空白），把 `username` 改为目标手机号，保持 `tenantId` 不变，重放请求。
3. 观察响应：若返回 `access_token`/`refresh_token` 且 `login_id` 为 `extend_<目标手机号>`，说明验证码校验被绕过。
4. 用该 token 请求个人信息接口，确认 `loginId`/`accountId`/手机号属于目标账户。
5. 对未注册号码重复同样请求，确认服务端自动创建账户；对已注册号码则直接登录，完成任意用户注册/接管。
6. 若前端只在登录响应中取 token，可进一步拦截响应并把 token 替换为目标账户 token，验证客户端是否无条件信任响应。

## PoC

```http
POST /xjky-server/xjky-biz-server/app/open/sms/registerAndLogin HTTP/1.1
Host: target
Content-Type: application/json;charset=UTF-8
Token:
Authorization: Bearer

{
  "openId": "",
  "password": "",
  "username": "<victim_phone>",
  "tenantId": "<tenant_id>"
}
```

响应（案例结构，值已占位）：

```json
{
  "code": 10000,
  "message": "成功",
  "data": {
    "access_token": "<JWT>",
    "refresh_token": "<JWT>",
    "token_type": "bearer",
    "expires_in": 86399,
    "scope": "all",
    "tenant_id": "<tenant_id>",
    "login_id": "extend_<victim_phone>",
    "user_id": "<user_id>",
    "user_name": null,
    "jti": "<jti>"
  }
}
```

用 token 查个人信息：

```http
GET /xjky-server/xjky-biz-server/app/.../userInfo HTTP/1.1
Host: target
Authorization: Bearer <access_token>
```

响应中的 `loginId`/`accountId` 若为目标手机号，即确认接管。

## 变体与关联

- 变体：空字符串、字段缺失、`null`、`" "`、`"0"`、数组/对象、重复参数等不同“空值”形态；不同框架对 `null` 与 `""` 的处理不同，需逐个尝试。
- 变体：验证码未绑定手机号/租户/场景，可用自己号码的验证码登录他人号码；参见 [[web-generic-auth-sms-login-code-not-bound-phone-parameter-tamper]]。
- 变体：验证码在响应包/跳转 URL 中回显，直接读取后登录；参见 [[web-generic-auth-sms-code-echo-response-arbitrary-login]]。
- 变体：同一验证码对多个号码有效；参见 [[web-generic-auth-sms-code-multi-number-shared-arbitrary-login]]。
- 变体：登录只校验手机号存在、不校验密码；参见 [[web-generic-auth-login-phone-any-password]]。
- 变体：篡改登录/验证响应包中的 `success`/`statusCode` 或 token；参见 [[web-generic-auth-password-reset-response-tampering-sms-bypass]]。
- 关联：[[web-generic-auth-applicantchange-pin-sms-bypass-registration]]（参数组合绕过短信校验并任意手机号注册）。
- 边界：若服务端对空值直接返回“验证码不能为空”，或验证码与手机号/租户强绑定且一次性使用，本链不成立；需要继续尝试缺失字段、类型混淆或响应篡改。

## 检测与防御

- **服务端强校验**：验证码必须非空、与手机号 + 租户 + 业务场景绑定、一次性使用、短有效期；空值/缺失/类型异常直接拒绝，不能进入“跳过校验”分支。
- **注册与登录分离**：注册必须完成短信验证；登录路径不要对未知手机号自动注册，或至少在自动注册前完成同样的验证码校验。
- **token 签发**：只有验证通过后才签发 token，并把 token 绑定到用户 ID、手机号、租户与设备；服务端维护会话，不信任客户端提交/替换的 token。
- **风控**：对同一 IP/设备/租户下大量不同手机号的注册/登录、空验证码请求、短时间 token 签发做限速与告警。
- **检测特征**：`openId`/`password`/`code` 为空或缺失的注册/登录请求；同一接口 `username` 高频变化；响应中 `login_id` 为 `extend_<phone>` 且与请求手机号一致；新设备直接使用 token 访问个人信息。
- **响应处置**：确认绕过后面临大量账户被接管，需重置受影响账户会话、吊销 token、排查异常注册/登录与后续操作。
