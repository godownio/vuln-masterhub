---
id: web-generic-auth-sms-captcha-type-param-validcode-removal-bypass
title: 短信接口用 type 参数决定是否校验图形验证码：改 type=0 并删除 validCode 直接发短信
type: scenario
domain: web
path: web/generic/auth
technique: sms-captcha-type-param-validcode-removal-bypass
aliases:
- 图形验证码删除绕过
- type=0 绕过验证码
- validCode 删除
- 短信验证码接口绕过
- 验证码字段可删除
tags:
- web
- auth
- captcha
- sms
- bypass
- business-logic
- parameter-tampering
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V288
  verified_at: '2026-11-08T05:27:23+08:00'
  notes: 已对照全文与43图核对：图22请求体mobile=...&type=1&validCode=x5qs&_csrf=0d7a2fc8...，原文标注改type为0并删除validCode；原文明确该改包可继续发送短信并用于短信轰炸。卡片对服务端按type分支解释与原文一致。dedup仅与验证码未绑定/空字段卡related，非同链；dup-scan与图形验证码回显卡pair判related，并列保留。未复现。
---

## 一句话结论

发送短信的接口根据客户端传入的 `type` 参数决定是否校验图形验证码：把 `type=1` 改为 `type=0` 并删除 `validCode` 字段后，后端走“无需验证码”的分支，短信仍被正常发送，攻击者可绕过图形验证码实施自动化短信轰炸。

## 原理

- 典型的发送短信请求体为 `mobile=...&type=1&validCode=x5qs&_csrf=...`。`type` 往往表示业务场景（如注册、找回密码、绑定手机），服务端可能按 `type` 选择不同校验逻辑。
- 如果服务端把“是否校验图形验证码”也绑定在这个客户端可控的 `type` 上，例如 `type == 1` 时才检查 `validCode`，那么攻击者把 `type` 改成 0（或其它无需验证码的场景值）就切换到了不校验的分支。
- 删除 `validCode` 字段进一步避免了“字段缺失时仍尝试比对”的实现；部分框架会把它解析为 `null`/空字符串，服务端若只在该字段非空时才校验，空值同样跳过。
- 根因是把“安全控制是否生效”交给了业务场景参数，而不是由服务端根据实际敏感操作独立决定。图形验证码因此不是安全边界，只是一个可被参数开关绕过的前端流程。
- 文章案例中，改 `type=0` 并删除 `validCode=x5qs` 后短信发送成功；结合接口缺少独立频率限制，可对同一号码连续发送，形成短信轰炸。

## 触发条件

- 发送短信接口接受客户端可控的 `type`、`scene`、`bizType`、`source` 等业务场景参数。
- 服务端用该参数分支决定是否校验图形验证码；至少存在一个不校验（或校验为空跳过）的分支。
- 接口没有独立于验证码的频率限制/配额，或限制可按手机号/IP 绕过。
- 攻击者能抓到完整请求并修改参数（无需登录或可用低权限会话）。

## 利用步骤

1. 在注册/找回密码页点击“发送验证码”，用 Burp 抓包，记录请求体中的 `mobile`、`type`、`validCode`、`_csrf` 等字段。
2. 先正常提交一次（带正确验证码），确认基线响应和短信到达。
3. 将 `type=1` 改为 `type=0`（或其它业务场景值），删除 `validCode` 字段，保持其余参数不变，发送。
4. 观察响应是否仍为成功、手机是否收到短信；若成功，说明验证码校验被绕过。
5. 对同一 `mobile` 重复发送，验证是否存在独立频率限制；若没有，即可造成短信轰炸。
6. 在授权范围内控制发送条数并记录证据，避免对真实用户造成大规模骚扰。

## PoC

```http
# 正常请求：type=1 时需要图形验证码
POST /reg/sendSmsCode HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Cookie: session=...

mobile=13800000000&type=1&validCode=x5qs&_csrf=0d7a2fc8-6ac5-47e1-82b4-3803d8867f31
```

```http
# 绕过：type 改为 0，删除 validCode 字段
POST /reg/sendSmsCode HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Cookie: session=...

mobile=13800000000&type=0&_csrf=0d7a2fc8-6ac5-47e1-82b4-3803d8867f31
```

## 变体与关联

- **字段置空**：不删除 `validCode`，改为 `validCode=`/`null`，若服务端“非空才校验”同样可能跳过。
- **切换业务场景**：尝试 `type=0/2/3`、`scene=register`、`bizType=login` 等值，寻找不校验验证码的分支。
- **验证码答案回显**：若服务端没有跳过分支，但把答案回显在响应中，可直接读取；参见 [[web-generic-auth-image-captcha-answer-response-echo]]。
- **频率限制绕过**：即使验证码被绕过，若存在独立限流，可结合 [[web-generic-auth-sms-bombing-rate-limit-bypass]] 的手机号变形/重放/XFF 手法。
- 关联：[[web-generic-auth-sms-code-empty-field-arbitrary-register-login]]（空验证码签发 token，属注册/登录接口的同类空值逻辑缺陷）。

## 检测与防御

- 不要用客户端可控的业务场景参数决定是否执行安全校验；短信发送接口应在服务端按操作类型强制校验图形验证码/行为验证。
- 验证码字段缺失、空值、`null` 一律视为校验失败，不要“非空才校验”。
- 对短信发送实施独立于验证码的多维限流：手机号 + 账号 + 真实 IP + 设备，使用原子计数与幂等键。
- 服务端记录每次发送的请求参数与验证码校验结果，对 `type` 异常切换、验证码字段缺失的请求告警。
- 检测：同一会话/号码短时间多次发送；请求中 `validCode` 缺失但 `type` 变化；短信网关侧对同一号码高频发送做二次拦截。
