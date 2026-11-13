---
id: web-generic-csrf-token-validation-request-method-get-bypass
title: CSRF Token 只在 POST 校验：切换 GET 方法绕过并借顶级导航完成 CSRF
type: scenario
domain: web
path: web/generic/csrf
technique: csrf-token-validation-request-method-differential
tags:
- web
- csrf
- token
- request-method
- get
- session
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:32:47+08:00'
  notes: 已对照原文《CSRF Token 1》节与图06-15核对：POST 缺 csrf 报 Missing，改 GET 后删 csrf 仍 302 改邮箱并解题，PoC 为顶级 GET 导航；方法分支校验结论与卡一致。PoC 未在浏览器实际执行。
url: /docs/web/generic/csrf/web-generic-csrf-token-validation-request-method-get-bypass/
draft: false
kb_aliases:
- CSRF Token 方法绕过
- POST 校验 GET 跳过
- GET 方法 CSRF
- token validation depends on request method
---

## 一句话结论

当应用只在 POST 请求上校验 CSRF Token、而同一状态变更接口也接受 GET 参数且 GET 分支跳过校验时，攻击者把修改邮箱等请求从 POST 改成 GET，再让受害者的浏览器以顶级导航访问该 GET URL，即可在携带会话 Cookie 的情况下完成 CSRF。

## 原理

- **校验逻辑按方法分支**：常见实现是在 POST 处理函数里读取并校验 `csrf` 参数，GET 处理函数直接按查询参数执行状态变更；或者框架的 Token 拦截器只挂在 POST 路由上。服务端因此认为“GET 是只读的，不需要 Token”，但业务代码实际用 GET 执行了写操作。
- **浏览器行为**：受害者已登录时，浏览器会自动为目标站点附带会话 Cookie。若 Cookie 为 `SameSite=Lax` 或未显式设置（Chrome 默认 Lax），顶级 GET 导航（点击链接、`location` 跳转、method=GET 表单提交）仍会携带 Cookie；因此跨站页面可以发起这次 GET。
- **为什么成立**：CSRF 防御的关键是“每个状态变更请求都要验证不可预测令牌”，而不是“只保护 POST”。方法判断与业务写操作不一致时，攻击者只需选择未受保护的动词。
- **验证要点**：先用受害者会话分别测试 POST 带/不带 Token、GET 带/不带 Token，确认 GET 分支不校验且确实修改数据；再构造只发 GET 的跨站页面。

## 触发条件

- 状态变更接口接受 GET 请求（或可通过参数/方法重写变成 GET），且 GET 分支不校验 CSRF Token。
- 接口仅依赖会话 Cookie 识别用户，无 Origin/Referer 强校验或其他令牌。
- 会话 Cookie 为 Lax/未显式设置，或攻击使用顶级导航（Strict 场景需另配合同站 gadget）。
- 目标操作可仅凭 URL 参数完成（如 `email=...`），不需要受害者输入不可预测值。

## 利用步骤

1. 用测试账号登录，抓取正常的 POST 修改请求；将其改为 `GET /path?email=attacker@example.com` 发送，观察是否 302/200 且数据被修改。
2. 若 GET 成功，删除 `csrf` 参数再测一次，确认 GET 分支完全不校验 Token。
3. 构造攻击页：用 `location` 跳转或 `method="GET"` 表单自动提交到该 GET URL。
4. 托管攻击页并把链接发给已登录受害者；受害者浏览器发起顶级 GET 导航，携带会话 Cookie，服务端执行修改。
5. 验证：受害者侧数据被改成攻击者指定值；若失败，检查 Cookie 是否 Strict、接口是否真的接受 GET、是否有 Origin/Referer 校验。

## PoC

```html
<script>
  location = "https://victim.example/my-account/change-email?email=attacker@evil.example";
</script>
```

或使用 GET 表单：

```html
<form action="https://victim.example/my-account/change-email" method="GET">
  <input type="hidden" name="email" value="attacker@evil.example">
</form>
<script>document.forms[0].submit();</script>
```

## 变体与关联

- [[web-generic-csrf-token-validation-presence-remove-parameter]]：另一种条件校验缺陷（参数缺失即跳过）。
- [[web-generic-csrf-samesite-lax-bypass-method-override]]：用 `_method` 参数在 GET/POST 之间重写方法，和本卡常组合使用。
- [[web-generic-csrf-missing-token-state-changing-endpoint]]：完全无 Token 的基础 CSRF。
- 变体：把 POST 改成 PUT/DELETE 等其它未校验方法；用 `X-HTTP-Method-Override` 头或 `_method` 参数切换动词。
- 边界：接口严格只读 GET、Token 校验覆盖所有方法、Cookie 为 SameSite=Strict 且无同站 gadget、或存在 Origin 校验时链断。

## 检测与防御

- 检测：同一状态变更接口同时存在 POST 与 GET 路由；GET 请求即可改变数据；日志中出现带业务参数的 GET 写操作。
- 防御：所有状态变更只允许 POST/PUT 等非安全方法，并对所有方法统一校验 CSRF Token；Token 绑定会话且不可预测；对 Cookie 显式设置 `SameSite=Lax/Strict`；校验 Origin/Referer 作为纵深防御。
- 响应：排查历史上通过 GET 执行的写操作，评估是否已被滥用。
