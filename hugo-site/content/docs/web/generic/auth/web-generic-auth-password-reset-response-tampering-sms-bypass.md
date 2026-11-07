---
id: web-generic-auth-password-reset-response-tampering-sms-bypass
title: 统一身份认证忘记密码：篡改响应包 success/statusCode 绕过短信验证码重置管理员密码
type: scenario
domain: web
path: web/generic/auth
technique: password-reset-client-response-trust
tags:
- web
- auth
- password-reset
- client-side-trust
- response-tampering
- sms-bypass
- account-takeover
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V72
  verified_at: '2026-11-05T16:53:23+08:00'
  notes: 已对照原文与图32-35核对：忘记密码身份验证后短信校验返回 meta.success=false/statusCode=500/您输入的手机验证码错误，原文将 false→true、500→200 后放行进入设置新密码并重置；最终 resetPassword 接口路径原文未展示，卡内为示意。未本地复现
url: /docs/web/generic/auth/web-generic-auth-password-reset-response-tampering-sms-bypass/
draft: false
kb_aliases:
- 忘记密码响应包篡改
- statusCode 500 改 200
- success false 改 true
- 短信验证码前端绕过
- 统一身份认证逻辑缺陷
---

## 一句话结论

统一身份认证的“忘记密码”流程如果只在前端根据验证码接口返回的 `success`/`statusCode` 决定是否进入下一步，攻击者用错误验证码触发失败响应，把 `success:false` 改为 `true`、`statusCode:500` 改为 `200` 后放行，就能跳过短信验证并直接重置管理员密码。

## 原理

- 正常的找回密码应在服务端维护“身份验证已通过”的状态：验证码校验成功后，服务端签发一次性 reset token 或写入会话标记，最终重置接口再次校验该状态。只在前端根据上一次响应决定页面跳转，等于把“是否验证通过”交给客户端。
- 案例中的验证码接口返回 JSON：`{"meta":{"success":false,"statusCode":500,"message":"您输入的手机验证码错误"},"data":null}`。前端根据 `success` 和 `statusCode` 判断失败；Burp 拦截响应，把 `success` 改为 `true`、`statusCode` 改为 `200`，前端便认为验证成功并进入设置新密码页面。
- 最终重置接口若只接收账号与新密码、不携带/不校验服务端验证凭证，就会直接改密；若校验了服务端 token，仅改响应包通常无法完成。
- 攻击前提是拿到账号标识与身份要素：案例中先通过公开操作手册/名单获得管理员账号、工号与身份证号，再用这些信息走到短信验证步骤；短信验证本身成为唯一门槛，而该门槛仅由前端判断。
- 根因是“客户端信任”与“验证状态未服务端化”，属于逻辑缺陷而非加密/协议问题。

## 触发条件

- 找回密码流程分多步，验证码校验接口返回可读的 `success`/`statusCode`/`code` 等字段，前端据此跳转；
- 最终重置密码接口不校验服务端签发的验证通过凭证（或凭证可预测/可绕过）；
- 攻击者掌握目标账号标识与身份要素（学号/工号、身份证号等，常来自公开名单或手册）；
- 能使用 Burp 等代理拦截并修改响应。

## 利用步骤

1. 收集目标账号与身份要素：公开操作手册、奖学金/评审名单中的工号/学号与姓名，必要时补全身份证号。
2. 进入“忘记密码”，输入账号与身份信息，进入短信验证码页面。
3. 随便输入错误验证码并提交，Burp 拦截响应。
4. 将响应中的 `success:false` 改为 `true`，`statusCode:500`/`code:500` 改为 `200`（字段名按目标实际响应调整），放行。
5. 前端跳转到设置新密码页面，设置攻击者已知的新密码。
6. 用新密码登录目标账号；若最终接口返回失败，说明服务端有二次校验，回到第 3 步检查是否有 reset token/会话标记需要一并伪造。

## PoC

```http
POST /uaa-service/checkSmsCode HTTP/1.1
Host: target.edu.cn
Content-Type: application/json

{"account":"<工号/学号>","phone":"<手机号>","smsCode":"000000"}
```

```json
// 原始失败响应
{"meta":{"success":false,"statusCode":500,"message":"您输入的手机验证码错误"},"data":null}

// Burp 修改后
{"meta":{"success":true,"statusCode":200,"message":"验证成功"},"data":null}
```

```http
POST /uaa-service/resetPassword HTTP/1.1
Host: target.edu.cn
Content-Type: application/json

{"account":"<工号/学号>","newPassword":"<新密码>"}
```

## 变体与关联

- 变体：字段名可能是 `code`、`ret`、`verified`、`result`；值可能是 `0/1`、`false/true`、`500/200`；有时还需同时改 HTTP 状态行。
- 变体：验证码校验成功但前端只检查响应长度/文本，可用相同手法；或验证码可爆破/回显/固定。
- 关联：[[web-generic-auth-freshman-reset-id-last6-public-pii]]（弱身份要素重置）、[[web-generic-auth-password-reset-username-tampering]]（重置表单用户名篡改）、[[web-generic-auth-weak-security-question-reset]]（弱密保问题）。
- 边界：服务端在最终重置时校验一次性 token、验证码尝试次数、会话绑定或短信回执时，单纯改响应包无效。

## 检测与防御

- 修复：验证码校验通过后由服务端签发一次性、短时效、绑定账号与设备的 reset token；最终重置接口必须校验该 token，不能只信前端状态。
- 加固：验证码错误次数限制、图形/行为验证码、短信发送频率限制；重置成功后强制下线并通知账号属主。
- 检测：监控“验证码接口返回失败但随后调用重置接口成功”的请求链；关注同一账号/设备短时间内多次重置；对异常响应修改无法直接检测，但可用服务端状态一致性审计发现。
