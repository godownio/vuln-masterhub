---
id: web-generic-auth-image-captcha-answer-response-echo
title: 图形验证码答案在发送验证码响应中明文回显：验证码形同虚设
type: scenario
domain: web
path: web/generic/auth
technique: image-captcha-answer-response-echo
aliases:
- 图形验证码回显
- 验证码答案泄露
- verificationCode 回显
- 图片验证码明文返回
- captcha 回显
tags:
- web
- auth
- captcha
- verification-code
- response-echo
- logic-flaw
- automation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V288
  verified_at: '2026-11-08T05:27:21+08:00'
  notes: 已对照全文与43图核对：图20忘记密码页发送短信；图21 POST /getVerificationCode 返回{"code":"2000","message":"SUCCESS","content":{"verificationCode":"KRAW"}}，与卡片示例逐字一致；KRAW为4位字母图形验证码答案。dedup仅与短信OTP回显卡related（对象不同），非同一链；dup-scan与type参数卡pair判related，裁定并列保留（回显答案 vs 校验分支删除）。未复现。
---

## 一句话结论

发送短信验证码的接口在 JSON 响应里直接返回图形验证码的答案（例如 `{"content":{"verificationCode":"KRAW"}}`），攻击者无需识别图片即可读取答案并原样提交，图形验证码原本用于阻止自动化请求的作用完全失效。

## 原理

- 图形验证码是 challenge-response：服务端生成随机字符串，渲染成图片给客户端，同时把答案存入 session；客户端提交用户输入的字符串，服务端按 session 比对。
- 该设计的安全性依赖“答案只存在于服务端与用户的大脑中，不随响应返回”。如果接口在生成/发送验证码的响应体中把答案（`verificationCode`、`captcha`、`code` 等字段）一并返回，任何能读 HTTP 响应的人都能拿到答案。
- 攻击者不需要 OCR、不需要人工看图，只要在脚本里解析 JSON、取出 `verificationCode`，再把它填进下一次请求的 `validCode` 字段即可通过校验。验证码从“人机区分”退化为“多一次请求”。
- 这类泄露常见于“发送短信验证码”这类复合接口：服务端为了前端展示或调试，把图形验证码对象（含答案）随响应返回；此后所有依赖该图形验证码的操作（发送短信、找回密码、注册、登录）都可被自动化。
- 危害取决于下游操作：若下游是短信发送，可放大为短信轰炸/费用损失；若下游是密码重置或注册，可配合验证码爆破或无限制尝试进一步扩大。文章案例展示的是修改密码流程中的发送验证码接口，响应直接返回 `verificationCode: KRAW`。

## 触发条件

- 存在“获取/发送验证码”接口，其响应 JSON/响应头/HTML 中包含图形验证码答案字段。
- 该答案与当前会话/请求绑定，服务端在后续提交时使用同一 session 校验。
- 后续敏感操作只要求提交图形验证码 + 手机号/账号，没有额外的行为验证或滑块。
- 攻击者能直接调用该接口（无需登录或可用低权限会话）。

## 利用步骤

1. 打开忘记密码/注册页，触发一次“获取验证码”，用 Burp 抓请求与响应。
2. 在响应中查找图形验证码答案字段，常见名称：`verificationCode`、`captcha`、`code`、`validCode`、`checkCode`；文章案例为 `content.verificationCode`，值为 `KRAW`。
3. 若响应中没有，检查响应头、Cookie、前端 JS 变量或跳转 URL；确认该值是图形验证码答案而非短信验证码。
4. 构造后续请求，把读到的答案填入 `validCode`/`captcha` 字段，连同手机号/账号提交。
5. 连续执行多次，确认每次都能通过；若答案每次变化，则在每次请求后重新读取。
6. 在授权范围内验证下游影响（短信条数、是否可进入下一步），不要对真实用户批量操作。

## PoC

```http
POST /getVerificationCode HTTP/1.1
Host: target.example
Content-Type: application/json

{"mobile":"13800000000"}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8

{"code":"2000","message":"SUCCESS","content":{"verificationCode":"KRAW"}}
```

```http
POST /resetPassword/checkCode HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded

mobile=13800000000&validCode=KRAW
```

## 变体与关联

- **短信验证码本身回显**：如果响应返回的是短信 OTP 而非图形验证码答案，危害直接升级为任意账号登录；已有 [[web-generic-auth-sms-code-echo-response-arbitrary-login]] 覆盖该情形，本卡的泄露对象是图形验证码答案。
- **验证码复用**：答案回显可与“验证码一次性失效缺失”叠加，进一步降低爆破成本；参见 [[web-generic-auth-captcha-client-refresh-session-reuse]]。
- **答案可预测/固定**：若 `verificationCode` 由时间戳、递增数或固定值生成，即使不回显也能预测，属于弱随机问题。
- **短信接口验证码参数可删除**：另一类绕过是直接删除验证码字段，参见 [[web-generic-auth-sms-captcha-type-param-validcode-removal-bypass]]。

## 检测与防御

- 永远不要把图形验证码答案返回给客户端；服务端只保存哈希/答案并与 session 绑定，响应只返回图片或一次性的 captcha key。
- 验证码一次性使用，校验后立即删除（无论成功失败），设置短有效期（如 2–5 分钟）。
- 对发送短信、重置密码等敏感操作增加服务端频率限制、行为验证或滑块；不要只依赖图形验证码。
- 代码审计/测试要点：搜索响应对象中是否包含 `verificationCode`、`captchaCode`、`answer` 等字段；检查生成验证码接口的返回结构。
- 监控：同一手机号/会话短时间大量获取验证码；同一验证码答案被重复提交；接口响应中出现验证码明文字段。
