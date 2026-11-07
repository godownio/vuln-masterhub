---
id: web-generic-auth-two-step-password-hidden-userid-header-trust
title: 两步认证登录链：未授权 /password/{username} + 隐藏 user_id + X-UserId 头信任导致任意用户身份伪造
type: scenario
domain: web
path: web/generic/auth
technique: multi-step-auth-hidden-userid-header-trust
aliases:
- 两步认证越权
- 密码页隐藏字段 user_id
- X-UserId 请求头信任
- Flask Session user_id 伪造
- 身份认证绕过链
tags:
- web
- auth
- idor
- broken-access-control
- header-trust
- session
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V106
  verified_at: '2026-11-05T22:26:55+08:00'
  notes: 已对照原文与图15/16核对：/password/{username} 未授权、隐藏 user_id 10032、篡改为 10031 后 302、X-UserId 头与 Flask Session user_id 均源自客户端，链路与报告一致；PoC 为按原文重写的 curl 模板，未本机复跑；原文无产品版本，不设 versions；frontmatter 无 sources/source_url。
---

## 一句话结论

两步认证流程中，密码页 `/password/{username}` 无需登录即可访问并泄露隐藏的 `user_id`；提交表单里的 `user_id` 可被篡改且服务端不校验它与 `username` 的绑定；密码提交端点又直接信任客户端 `X-UserId` 请求头，Flask Session Cookie 中的 `user_id` 同样源自该客户端值。三者串起来，攻击者无需知道密码即可伪造任意用户身份登录。

## 原理

- 认证流程是 `/`（输入用户名）→ `/password/{username}`（输入密码）→ `/dashboard`。第一步只验证用户名存在，第二步才验证密码。
- 密码页无需登录即可访问，页面 HTML 中的隐藏字段直接泄露内部 `user_id`（如 10032）和用户名（如 John），可枚举其他用户。
- 密码提交端点是 `POST /password/{username}`，请求体包含 `username`、`user_id`、`password`。服务端没有校验 `user_id` 与 `username` 的绑定关系，攻击者把 `user_id` 改成其他用户（如 10031）后仍返回 302 → `/dashboard?username=test`，即按篡改后的 user_id 建立会话。
- 更重要的是，该端点直接信任客户端发送的 `X-UserId` 请求头来确定用户身份；登录成功后签发的 Flask Session Cookie 中 `user_id` 字段（Base64 解码为 `{"user_id":10032}`）也来源于客户端提交的 `X-UserId`，而不是服务端认证结果。攻击者可以任意篡改头值或 Cookie 中的 user_id，伪造其他用户身份完成认证。
- 登录页 HTML 注释还泄露了测试账号 `test:test`，为攻击者提供了可用的初始凭据；即使没有该凭据，未授权的密码页也足以枚举 user_id。

## 触发条件

- 目标采用“用户名页 → 密码页 → Dashboard”的两步认证流程；
- `/password/{username}` 未要求先完成第一步认证，页面包含 `user_id` 隐藏字段；
- 密码提交端点信任请求体 `user_id` 或 `X-UserId` 等客户端身份字段；
- Session 中的身份字段由客户端值派生，而不是服务端认证态；
- 攻击者能访问登录相关接口（无需已登录）。

## 利用步骤

1. 访问 `/password/<已知或枚举到的用户名>`，确认无需登录即可打开密码页；查看 HTML 源码，提取隐藏字段 `user_id` 与用户名。
2. 输入任意密码提交，观察请求：定位 `POST /password/{username}` 的 `username`、`user_id`、`password` 参数，以及是否存在 `X-UserId` 头。
3. 将 `user_id` 改为另一个用户的值（如 10031），或把 `X-UserId` 头改为目标用户 ID，重新提交。
4. 观察响应：若返回 302 且 Location 指向 `/dashboard?username=<目标>`，说明服务端按篡改后的 user_id 建立了会话。
5. 使用返回的 Flask Session Cookie 访问 `/dashboard` 与 `/orders`，确认已进入目标用户上下文；如需扩大影响，可枚举 user_id 批量尝试。

## PoC

```bash
# 1. 未授权访问密码页，提取隐藏 user_id
curl -s 'http://<target>/password/test' | grep -iE 'user_id|username'

# 2. 提交密码时篡改 user_id（以及 X-UserId 头）
curl -s -i -X POST 'http://<target>/password/test' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'X-UserId: 10031' \
  --data 'username=test&user_id=10031&password=test'

# 预期：HTTP/1.1 302 Found
# Location: /dashboard?username=test
# 随后携带返回的 session Cookie 访问 /dashboard 与 /orders
```

原文还发现登录页 HTML 注释泄露测试凭据：

```html
<!-- TODO: Delete the testing account (test:test). -->
```

可用 `test:test` 先进入流程，再按上述步骤篡改 user_id。

## 变体与关联

- 变体：只篡改隐藏字段 `user_id`，不碰 `X-UserId`。若服务端从请求体取身份，同样成立。
- 变体：直接修改 Session Cookie 中的 `user_id`（Base64 JSON），若服务端不验签或签名密钥泄露，可绕过登录直接伪造会话。
- 变体：通过未授权的 `/password/{username}` 枚举 user_id，再结合弱口令/测试账号扩大接管范围。
- 关联 [[web-generic-auth-password-reset-username-tampering]]：同样利用隐藏字段/用户名参数篡改身份；本卡是登录流程内的多步链。
- 关联 [[web-generic-auth-gettokenbyid-userid-token-issuance]]：服务端按客户端 userId 签发身份凭据的同类问题。
- 边界：若服务端在密码校验后从数据库按 username 查询 user_id、忽略客户端提交值，或 Session 使用服务端签名且不包含客户端可控身份，本链不成立。

## 检测与防御

- **身份服务端绑定**：密码校验通过后，由服务端按 username 从数据库查询 user_id；忽略请求体中的 `user_id`、`X-UserId`、`X-User-Id` 等身份字段。
- **认证流程完整**：`/password/{username}` 必须要求第一步已通过（短期、签名的流程令牌），不能仅凭用户名直接进入密码页；页面不得回显内部 user_id。
- **会话安全**：Session Cookie 使用服务端签名，身份字段由服务端认证态写入；不要从客户端头派生 Session 内容。
- **清理泄露**：删除 HTML 注释中的测试账号；生产环境移除默认/测试用户。
- **检测**：审计登录相关端点是否读取 `X-UserId`、`user_id` 等客户端字段；对同一会话短时间切换 user_id、枚举 `/password/*` 的行为告警；用低权/无凭据请求测试未授权访问。
