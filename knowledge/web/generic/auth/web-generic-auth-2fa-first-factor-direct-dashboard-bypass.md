---
id: web-generic-auth-2fa-first-factor-direct-dashboard-bypass
title: 登录后 2FA 仅前端跳转：直接访问受保护路由绕过二次验证
type: scenario
domain: web
path: web/generic/auth
technique: 2fa-first-factor-direct-route-bypass
aliases:
- 2FA 绕过
- 二次验证绕过
- 直接访问 dashboard
- 2FA 未强制
- 认证状态只存前端
- first-factor bypass
tags:
- auth
- 2fa
- mfa
- access-control
- broken-authentication
- session
- frontend
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V206
  verified_at: '2026-11-07T02:23:47+08:00'
  notes: 已对照原文与图18-19核对：登录后跳 /2FA，但同一会话直接 GET /admin/dashboard 返回月球文件管理系统后台页面，未完成 2FA；卡内直接访问受保护路由的结论成立。未复跑 PoC；原文未展示 dashboard API 级鉴权差异，卡内已注明继续测 /admin/download 等入口。
---

## 一句话结论

应用在用户名/口令校验通过后只把浏览器重定向到 `/2FA` 页面，但后端会话只标记“第一因子已通过”，没有在所有受保护路由上强制“第二因子已完成”；攻击者拿到有效口令后直接访问 `/admin/dashboard`（或对应 API）即可跳过 2FA，2FA 页面只起到提示作用而不构成安全边界。

## 原理

- 常规多因子流程：第一因子校验成功后，服务端应把会话标记为“半认证（pending_2fa）”，只允许访问 2FA 验证接口；第二因子通过后再把会话升级为“完全认证”。所有受保护路由/API 都必须检查该状态。
- 案例实现：登录成功即建立完整会话，前端 `window.location` 跳到 2FA 页面；`/admin/dashboard` 只检查“是否登录”，不检查“是否完成 2FA”。攻击者可以直接请求 dashboard，甚至不需要访问 2FA 页面。
- 即使后端有 2FA 校验接口，如果 dashboard 的控制器/中间件没有串到该状态，2FA 就是可选的 UI 步骤；攻击者可用 curl/Burp 直接跳过。
- 这类缺陷常与“2FA 状态存 localStorage/sessionStorage/前端路由守卫”叠加：客户端可以改状态或绕过守卫，服务端仍信任请求。
- 为什么可行：认证状态是服务端会话的属性，必须由服务端在每个受保护入口检查；仅靠前端跳转/页面隐藏不改变服务端的授权决策。

## 触发条件

- 应用存在两阶段登录（口令 + 2FA），但第二因子不是服务端强制的会话升级条件。
- 攻击者已获得有效第一因子（弱口令、泄露凭据、撞库、备份文件等）。
- 受保护路由/API 只检查“已登录”，未检查 `2fa_verified`/`mfa_passed` 等会话字段。
- 2FA 页面与业务页面使用同一会话 Cookie，且业务接口不依赖一次性 2FA token。

## 利用步骤

1. 用窃取/猜解的第一因子正常登录，记录响应状态、Cookie 与重定向地址（通常跳 `/2FA`）。
2. 不访问 2FA 页面，直接用同一 Cookie 请求受保护路由，如 `GET /admin/dashboard`、`GET /admin/files`、`GET /api/admin/users`。
3. 若返回 200/业务数据，说明 2FA 未在服务端强制；继续枚举后台与管理 API。
4. 若 dashboard 被重定向回 `/2FA`，尝试：直接调用业务 API（可能不经过页面控制器）、修改 `mfa`/`verified` Cookie/JSON 字段、用 2FA 页面的“跳过/稍后”参数、或换 HTTP 方法/路径大小写。
5. 若第一因子凭据来自备份文件/源码泄露（如编辑器临时文件 `login.html~`、`.gitignore_test` 等），把该来源写入报告，说明凭据泄露与 2FA 绕过叠加。
6. 验证后登出并清理测试数据。

## PoC

```http
# 1) 第一因子登录，获取会话
POST /login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

email=admin%40example.com&password=<leaked-password>&csrf_token=<token>

# 2) 不访问 /2FA，直接请求受保护页面
GET /admin/dashboard HTTP/1.1
Host: target
Cookie: session=<第一因子会话>
```

```text
预期：直接返回 dashboard/后台数据，而浏览器流程本应在 /2FA 停留。
若 dashboard 页面正常但 API 仍拒绝，继续测试 /admin/download、/admin/files、/api/admin/* 等未挂 2FA 检查的入口。
```

```python
import requests
s = requests.Session()
s.post("http://target/login", data={"email": "admin@example.com", "password": "leaked"})
r = s.get("http://target/admin/dashboard")
print(r.status_code, r.text[:200])   # 200 且含后台内容 => 2FA 被跳过
```

## 变体与关联

- 变体：2FA 状态存在 localStorage/sessionStorage/前端路由 meta，攻击者直接改值为 `true` 或绕过路由守卫。
- 变体：2FA 只在登录响应中检查，业务 API 完全不看会话状态；或只有部分路由挂了 2FA 中间件。
- 变体：2FA 验证接口存在 IDOR/用户参数篡改，可为他人会话置为已验证（参见 2FA 参数篡改/验证码爆破卡）。
- 变体：第一因子凭据来自 robots.txt 暴露的备份文件、编辑器临时文件（`login.html~`）、`.gitignore` 误命名导致未忽略等。
- 关联：[[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]（篡改用户参数/爆破 2FA 码）、[[web-generic-auth-2fa-answer-count-key-presence-bypass]]（2FA 答案计数/键存在绕过）、[[web-generic-auth-vue-router-frontend-guard-bypass]]（前端路由守卫不是安全边界）、[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（同题后续任意文件读取）。

## 检测与防御

- 修复：第一因子通过后会话标记为半认证，所有受保护路由/API 统一中间件检查“第二因子已完成”；未完成时只允许访问 2FA 验证接口与登出。
- 修复：2FA 状态只存服务端会话/数据库，前端不得作为授权依据；验证成功后轮换会话 ID，防止固定/劫持。
- 加固：2FA 验证接口限速、一次性 token、绑定当前会话；敏感操作二次验证。
- 检测：登录后未调用 2FA 接口却访问后台/管理 API；同一会话在 `/2FA` 与 dashboard 之间异常跳转；直接访问后台路径返回 200 而浏览器流程要求 2FA。
