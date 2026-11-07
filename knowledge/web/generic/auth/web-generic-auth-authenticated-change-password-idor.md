---
id: web-generic-auth-authenticated-change-password-idor
title: 登录后改密接口越权：username 可控导致修改他人密码
type: scenario
domain: web
path: web/generic/auth
technique: authenticated-change-password-idor
aliases:
- 改密接口越权
- change-password username 篡改
- 低权限用户改管理员密码
- current-password 爆破
- 认证后 IDOR
tags:
- auth
- idor
- password-change
- account-takeover
- bruteforce
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:13:36+08:00'
  notes: 已对照 Level 21 change-password.php 的 username=administrator 与 current-password 爆破截图核对；未验证点：截图仅展示 New passwords do not match，成功改密过程未完整展示
---

## 一句话结论

已登录的低权限用户访问“修改密码”接口时，如果接口用请求中的 `username` 定位目标用户、且只校验当前会话已登录而不校验 username 与会话用户一致，就可以把 username 改成管理员，并通过响应差异爆破/校验其当前密码后设置新密码，接管管理员账户。

## 原理

- 正常的改密接口应从会话中取当前用户，只允许修改自己的密码，并要求输入当前密码。
- 漏洞实现把 `username` 作为请求参数传给后端查询用户，后端只检查“请求已登录”，没有检查 `session.username == request.username`；于是任何登录用户都能指定任意目标。
- 接口通常还会校验 `current-password`。如果校验逻辑对目标用户执行、且没有尝试次数限制，攻击者可以把 current-password 作为爆破点，用响应差异（“当前密码错误” vs “新密码不一致/成功”）判断正确密码。
- 另一种实现完全不需要 current-password，直接提交 username + new-password 即可重置，危害更大。
- 该漏洞与密码重置的区别是：攻击者已有一个合法低权限账号，利用的是认证后的越权，而非未认证的重置流程。

## 触发条件

- 攻击者拥有一个可登录的低权限账号。
- 改密接口接受客户端提交的 `username`/`user_id` 等目标标识，且未做会话一致性/权限校验。
- 接口对 current-password 的校验可被爆破（无速率限制）或根本不需要。
- 目标管理员账号存在且用户名可知/可枚举。

## 利用步骤

1. 用低权限账号登录，进入修改密码页面，抓取提交请求。
2. 观察请求中是否有 `username`、`user_id`、`account` 等参数；将其改为 `administrator`。
3. 先提交一组新密码，观察响应：若提示当前密码错误，则 current-password 是校验点；若直接成功，则已完成越权改密。
4. 若需要 current-password，固定 username 为目标，对 current-password 做字典/常见口令爆破；用响应长度/文案/状态码过滤失败。
5. 命中后设置新密码，退出并用管理员账号登录验证。
6. 成功后停止，记录请求与响应；避免锁定目标账号。

## PoC

越权改密请求：

```http
POST /Expert/level19/change-password.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: lab32_user=admin

username=administrator&current-password=<candidate>&new-password-1=NewPass123&new-password-2=NewPass123
```

current-password 爆破（Burp Intruder）：

```text
Attack type: Sniper
Payload position: current-password=§123456§
Payload: 常见弱口令字典
Filter: 排除包含 "Current password is incorrect" 的响应
```

若接口不校验 current-password，可直接：

```http
username=administrator&new-password-1=NewPass123&new-password-2=NewPass123
```

## 变体与关联

- 变体：`user_id`/`account`/`email` 作为目标标识；尝试越权到其他角色。
- 变体：接口要求旧密码但只校验长度/格式，或可被空值/数组/类型混淆绕过。
- 变体：通过批量接口/GraphQL mutation 修改他人密码；或通过资料更新接口改邮箱后走重置流程。
- 关联：[[web-generic-auth-password-reset-username-tampering]]（未认证的重置流程同类问题）。
- 关联：[[web-generic-auth-login-bruteforce-response-payload]]（current-password 爆破的响应判读）。
- 注意：测试时使用授权账号，不要锁定生产管理员；优先验证“是否需要 current-password”，再决定是否爆破。

## 检测与防御

- 防御：目标用户必须从服务端会话获取，禁止客户端提交 username/user_id 作为改密目标；如需管理员代改，单独接口 + 严格 RBAC + 审计。
- 防御：修改自己密码时必须验证 current-password；对失败次数限速/锁定；新密码强度校验；改密后强制其他会话下线并通知用户。
- 防御：对改密接口做 CSRF 防护与二次认证（高风险操作）。
- 检测：同一会话修改的用户名与会话用户不一致；短时间大量 current-password 失败；管理员密码被非管理员会话修改；改密后立即出现管理员登录。
