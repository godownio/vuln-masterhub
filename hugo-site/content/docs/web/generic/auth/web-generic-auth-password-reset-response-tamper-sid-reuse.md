---
id: web-generic-auth-password-reset-response-tamper-sid-reuse
title: 密码重置：篡改验证码响应 + 复用发码请求中的 sid 重置管理员密码
type: scenario
domain: web
path: web/generic/auth
technique: password-reset-response-tamper-sid-reuse
tags:
- web
- auth
- password-reset
- response-tampering
- sid-reuse
- account-takeover
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:23:31+08:00'
  notes: 已对照原文与 img/06-11 核对：validatecode2 响应 status 0 改 1、发码请求 sid=7acee75597...、findpwdsetpwd.do 复用 sid、flag:true 成功响应一致；dedup_review 中与 sms-bypass 卡的差异（sid 复用步骤）成立，保留。
url: /docs/web/generic/auth/web-generic-auth-password-reset-response-tamper-sid-reuse/
draft: false
kb_aliases:
- 返回包 status 篡改
- sid 复用重置密码
- 验证码校验绕过
- findpwdsetpwd
- validatecode2
- 密码重置逻辑漏洞
---

## 一句话结论

找回密码流程中，验证码校验接口只根据返回包里的 `status` 字段决定前端是否进入下一步；用错误验证码触发失败响应，把 `status:0` 改成 `1` 放行后，重置接口因缺少 `sid` 报错，而该 `sid` 已经在更早的“发送邮箱验证码”请求中返回，把它复用进重置请求即可完成管理员密码重置。

## 原理

- 正常的找回密码应在服务端维护“验证码已验证通过”的状态：验证码校验成功后签发一次性 reset token/sid，最终重置接口再次校验该状态。案例中前端只看 `status` 字段决定页面跳转，等于把“是否通过验证”交给客户端。
- 攻击者输入错误验证码（如 `123456`），拦截 `validatecode2` 响应，把 `{"status":0}` 改为 `{"status":1}`；前端据此进入“重置密码”步骤。
- 但重置接口需要 `sid`，而由于验证码并未真正通过，服务端没有为本次流程生成可用的 sid，页面报“sid 为空”。
- 关键缺陷是：`sid` 并不是验证成功后新签发的，而是在发送验证码请求（`sysid`/`sid` 参数）阶段就已经返回给客户端，并且没有和“验证码校验通过”绑定。攻击者从前面正常的发码响应中取回 `sid`，粘贴到 `findpwdsetpwd.do` 的重置请求中，服务端校验通过，密码被重置。
- 根因是“客户端信任响应字段”加“验证状态 Token 提前泄露/未绑定校验结果”两个逻辑缺陷叠加；仅改响应包或仅复用 sid 都不足以完成。

## 触发条件

- 找回密码为多步流程，验证码校验接口返回可读的 `status`/`code`/`success` 字段，前端据此跳转。
- 最终重置接口需要 `sid`/token，但该值在发码阶段就返回给客户端，且未与验证码校验结果绑定。
- 攻击者知道目标账号（文章为 `admin`）及对应邮箱/身份信息，能触发发码。
- 能使用 Burp 等代理拦截并修改响应/请求。

## 利用步骤

1. 在找回密码入口输入 `admin` 与正确图形验证码，进入安全验证步骤。
2. 点击“获取验证码”，拦截发码请求，记录其中的 `sid`/`sysid` 值（文章为 `sid=7acee75597...`）。
3. 输入任意错误邮箱验证码（如 `123456`），提交 `validatecode2` 请求，拦截响应。
4. 把响应中的 `"status":0` 改为 `"status":1`（字段名按目标调整），放行，使前端进入重置密码步骤。
5. 输入新密码提交；若提示 `sid` 为空或校验失败，把第 2 步记录的 `sid` 填入重置请求（文章为 `findpwdsetpwd.do`）。
6. 若返回 `{"flag":true,...}` 或提示“密码修改成功”，用新密码登录目标账号。

## PoC

发码请求中记录 sid（字段名以目标为准）：

```http
POST /<send-code-path> HTTP/1.1
Content-Type: application/x-www-form-urlencoded

sysid=&sid=7acee75597...&userCode=admin&countryCode=86&type=normal&isAjax=1&locale=zh_CN
```

验证码校验响应篡改：

```http
POST /<validate-code-path> HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=admin%40example.com&code=123456&userId=<id>&isAjax=1
```

```json
// 原始失败响应（示意）
{"status":0,"msg":"验证码错误"}

// Burp 修改后
{"status":1,"msg":"timeout"}
```

重置密码并复用 sid：

```http
POST /<reset-password-path> HTTP/1.1
Content-Type: application/x-www-form-urlencoded

userid=<id>&shaNewPassword=<新密码哈希>&tpwd=<哈希>&sid=7acee75597...&encrypted=&isAjax=1&locale=zh_CN
```

成功响应：

```json
{"flag":true,"extinfo":1,"code":0}
```

## 变体与关联

- 变体：`status` 字段可能叫 `code`、`success`、`ret`、`verified`；值可能是 `0/1`、`false/true`、`500/200`；有时还需同时改 HTTP 状态行。
- 变体：`sid` 可能出现在发码响应、上一步页面 HTML、URL 或 Cookie 中；若 sid 与用户/会话绑定不严，可复用或替换成受害者账号的 sid。
- 关联：[[web-generic-auth-password-reset-response-tampering-sms-bypass]]（同样利用响应包篡改跳过验证码；本卡补充“发码阶段 sid 泄露并在重置接口复用”的关键一步，解决最终接口需要服务端凭证的问题）。
- 关联：[[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]（验证码未与用户/会话绑定）。
- 边界：最终重置接口若校验“验证码已通过”的一次性 token（而不是提前返回的 sid），且 token 与本次验证结果绑定，则响应篡改 + sid 复用不成立。

## 检测与防御

- 检测：验证码校验响应被篡改为成功但服务端无验证记录；重置请求中的 sid 来自更早的发码响应；同一 sid 在验证失败后仍被用于重置。
- 防御：验证码校验通过后由服务端签发一次性、短时效、与用户/会话/验证结果绑定的 reset token；重置接口必须校验该 token，不能接受发码阶段的 sid。
- 加固：发码阶段不要返回可用于重置的 sid/token；前端跳转仅作展示，服务端必须独立维护步骤状态；限制验证码尝试次数并记录异常。
