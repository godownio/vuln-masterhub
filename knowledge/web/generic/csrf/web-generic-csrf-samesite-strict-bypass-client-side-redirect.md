---
id: web-generic-csrf-samesite-strict-bypass-client-side-redirect
title: SameSite=Strict 绕过：用同站客户端重定向 gadget 制造站内第二跳
type: scenario
domain: web
path: web/generic/csrf
technique: samesite-strict-client-side-redirect-bypass
aliases:
- SameSite Strict 绕过
- 客户端重定向 CSRF
- 同站 gadget 二次请求
- postId 路径遍历重定向
- samesite strict bypass client-side redirect
tags:
- web
- csrf
- samesite
- strict
- client-side-redirect
- path-traversal
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:33:04+08:00'
  notes: 已对照原文 SameSite 绕过方式 1 与图56-61 核对（该节后续截图位于远程 ali URL，未随文章下载，按正文步骤核对）：postId 客户端重定向 gadget、路径遍历 1/../../my-account、GET 改邮箱；卡片机制与原文一致。PoC 未执行。
---

## 一句话结论

`SameSite=Strict` 的 Cookie 不会随跨站请求发送，但如果站点内存在“用攻击者可控参数拼出跳转目标”的客户端重定向 gadget，攻击者可以先让受害者跨站打开该同站 gadget，gadget 在站内发起第二次请求，这次请求由同站页面发起、会携带 Strict Cookie，从而绕过限制完成 CSRF。

## 原理

- **SameSite 按每次请求的发起方判断**：Strict Cookie 只在“发起方与目标同站”时发送。服务端 302 重定向不算绕过，因为浏览器仍按原请求的发起方判定；但客户端重定向（JS `location`、`window.location`）是站点页面自己发起的全新请求，浏览器视为同站导航，会附带 Strict Cookie。
- **客户端重定向 gadget**：常见于确认页/中转页，例如 `commentConfirmationRedirect.js` 里 `window.location = blogPath + '/' + postId`；`postId` 来自 URL 参数且未校验，攻击者可用路径遍历 `1/../../my-account/change-email?email=...` 把第二跳指向任意站内端点。
- **为什么能改数据**：目标站点的修改接口同时接受 GET（或 gadget 可构造等效 GET），且无 CSRF Token；第二跳在站内发起，Strict Cookie 被发送，服务端按正常用户处理。
- **验证要点**：确认 Strict Cookie 确实阻止直接跨站请求；再确认某个同站页面能把参数拼进 `location`/`window.open` 并可路径遍历到目标端点。

## 触发条件

- 会话 Cookie 为 `SameSite=Strict`（或等效严格限制）。
- 站点内存在客户端重定向 gadget：跳转目标可由 URL 参数控制，且可通过路径遍历/绝对 URL 等方式指向任意站内路径。
- 目标状态变更接口接受 GET 或 gadget 能构造其请求，且无 CSRF Token。
- 受害者已登录，攻击者能诱导其访问外部攻击页。

## 利用步骤

1. 确认目标 Cookie 为 Strict：直接跨站 POST/GET 时请求不携带 Cookie。
2. 寻找客户端重定向：浏览确认页、登录中转页，查看 JS 中是否用 URL 参数拼接 `location`；测试把参数改成不存在的路径，观察是否跳转到注入路径。
3. 测试路径遍历：如 `/post/comment/confirmation?postId=1/../../my-account`，确认能跳转到账户页。
4. 确认目标修改接口 GET 可用且无 Token（直接带受害者 Cookie 请求测试）。
5. 构造攻击页：让受害者浏览器先访问该同站 gadget URL，`postId` 指向 `1/../../my-account/change-email?email=attacker@evil.example`；gadget 的第二跳在站内发出并携带 Strict Cookie。
6. 投递攻击页，观察数据被修改；若 query 在路径拼接中被截断，可用编码或其它 gadget 形式调整。
7. 验证：网络面板中第二跳请求携带了会话 Cookie；失败时检查 gadget 是否仅允许白名单路径、目标接口是否只收 POST。

## PoC

```html
<script>
  // 先由第三方页面把受害者送到同站 gadget，gadget 再在站内跳到修改接口
  location = "https://victim.example/post/comment/confirmation?postId=1/../../my-account/change-email?email=attacker@evil.example";
</script>
```

若函数把 `postId` 拼成 `blogPath + '/' + postId`，`1/../../my-account/change-email?...` 会解析到 `/my-account/change-email?...`。

## 变体与关联

- [[web-generic-csrf-samesite-strict-bypass-sibling-domain-cswsh]]：另一条 Strict 绕过（兄弟域 + WebSocket）。
- [[web-generic-csrf-token-validation-request-method-get-bypass]]：目标接口 GET 可用的前提。
- [[web-generic-csrf-missing-token-state-changing-endpoint]]：无 Token 基础场景。
- 变体：客户端跳转可换成 `window.open`、meta refresh、iframe 注入、XSS；路径遍历可换成开放重定向到站内绝对 URL。
- 边界：gadget 校验目标路径、会话 Cookie 有其它绑定、目标接口只接受 POST 且无方法重写时链断。

## 检测与防御

- 检测：客户端 JS 中出现用 URL 参数拼接 `location`/`window.open` 的代码；路径遍历字符进入跳转目标；Strict Cookie 在站内第二跳后出现状态变更。
- 防御：客户端跳转目标使用白名单或映射表，禁止直接拼接用户输入；对路径做规范化与拒绝 `..`；状态变更只允许 POST + CSRF Token；Cookie 显式设置 `SameSite=Strict` 仅作为纵深防御。
- 响应：审计跳转参数与站内写操作日志。
