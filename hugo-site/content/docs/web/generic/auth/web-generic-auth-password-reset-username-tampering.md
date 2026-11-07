---
id: web-generic-auth-password-reset-username-tampering
title: 任意用户密码重置：重置表单 username 隐藏字段可篡改
type: scenario
domain: web
path: web/generic/auth
technique: password-reset-username-tampering
tags:
- auth
- password-reset
- parameter-tampering
- account-takeover
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:13:32+08:00'
  notes: 已对照 Level 15 重置流程与隐藏 username 表单源码核对；未验证点：原文未逐步展示 token 与 username 的解绑过程，POST 截图与成功提示的用户名存在歧义
url: /docs/web/generic/auth/web-generic-auth-password-reset-username-tampering/
draft: false
kb_aliases:
- 任意用户密码重置
- 密码重置 username 篡改
- 重置 token 未绑定用户
- reset_password.php username
- 找回密码逻辑漏洞
---

## 一句话结论

当密码重置流程把 `username` 放在隐藏字段或 POST body 中由客户端回传，且服务端在设置新密码时只校验 token 存在、不校验 token 与用户绑定关系（或不重新认证），攻击者就可以在提交新密码时把 username 改成管理员，从而重置任意用户密码并接管账户。

## 原理

- 正常流程：用户提交用户名 → 服务端生成一次性 token 并绑定该用户 → 邮件链接携带 token → 用户点击后设置新密码 → 服务端用 token 查回用户并更新。
- 漏洞实现：token 只作为“已通过邮件验证”的凭证，重置接口同时信任客户端提交的 `username` 字段；攻击者用自己的账号或任意 token 进入重置页，提交时把 username 改为 `administrator`，服务端便更新管理员密码。
- 另一种实现：token 与用户绑定，但重置页把 username 作为隐藏字段回传，服务端不比对 token 对应用户与提交的 username，导致任意用户重置。
- 该漏洞的关键是“用户身份在客户端可改”，而不是 token 可预测；即使 token 随机且一次性，只要 username 被信任，攻击者仍可改目标。

## 触发条件

- 密码重置流程存在“提交用户名 → 邮件链接 → 设置新密码”多步。
- 设置新密码的请求包含 `username`（隐藏字段、URL 参数、JSON body）且服务端使用它定位用户。
- 服务端未校验 token 与 username 的绑定，或未在设置密码时要求原密码/会话。
- 攻击者能访问重置页（自己的邮箱/ token，或 token 可复用）。

## 利用步骤

1. 用自己的账号发起密码重置，获取重置链接/token。
2. 打开重置页，抓取提交新密码的 POST 请求。
3. 观察请求中是否有 `username`、`user`、`email` 等标识；将其改为目标管理员用户名。
4. 提交新密码；若返回成功，用新密码登录管理员账户验证。
5. 若 username 不在表单中，尝试在 URL/JSON/隐藏字段中补充；若 token 与用户绑定，尝试同时替换 token 或寻找 token 可预测/可复用。
6. 成功后立即停止，记录证据；避免破坏生产数据。

## PoC

漏洞表单示例：

```html
<form action="reset_password.php" method="POST">
    <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">
    <input type="hidden" name="username" value="<?php echo htmlspecialchars($username); ?>">
    <input name="new_password" type="password">
    <input name="confirm_password" type="password">
    <input type="submit" value="提交更改">
</form>
```

篡改请求：

```http
POST /reset_password.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

token=<own-valid-token>&username=administrator&new_password=NewPass123&confirm_password=NewPass123
```

成功响应通常为“密码已成功重置”；随后用 `administrator/NewPass123` 登录验证。

## 变体与关联

- 变体：username 放在 URL query 中，重置页直接读取；改为管理员用户名即可。
- 变体：token 可预测/可枚举，或 token 不一次性、可复用；可绕过邮箱验证。
- 变体：通过修改 email/phone 字段重置目标账户；或利用 Host 头污染把 token 发给攻击者（见关联卡）。
- 关联：[[web-generic-auth-password-reset-host-header-poisoning]]（重置链接 Host 头注入窃取 token）。
- 关联：[[web-generic-auth-authenticated-change-password-idor]]（登录后改密接口的同类越权）。
- 关联：[[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]（认证流程中的 username 参数篡改）。
- 注意：token 与用户绑定是否正确，需通过“用自己的 token + 他人 username”与“他人 token + 自己 username”两组对照验证。

## 检测与防御

- 防御：token 必须绑定用户（服务端存储 token→user_id），设置密码时只从 token 解析用户，不接受客户端 username/email。
- 防御：token 一次性、短过期、随机强；使用后立即失效；重置成功后通知原邮箱并强制下线。
- 防御：设置新密码前要求原密码或已认证会话（按业务风险选择）；对重置请求做 CSRF 防护。
- 检测：重置请求中的 username 与 token 对应用户不一致；同一 token 被多次使用；短时间大量重置请求；重置后立即登录成功；邮件链接域名异常。
