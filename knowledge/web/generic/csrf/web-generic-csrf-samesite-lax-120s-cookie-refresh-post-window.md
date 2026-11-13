---
id: web-generic-csrf-samesite-lax-120s-cookie-refresh-post-window
title: SameSite=Lax 绕过：Chrome 顶级 POST 前 120 秒豁免窗口（登录后立即投递）
type: scenario
domain: web
path: web/generic/csrf
technique: samesite-lax-120s-post-grace-window
aliases:
- SameSite Lax 120 秒
- Lax + POST 豁免
- Chrome 默认 Lax 绕过
- cookie refresh samesite bypass
- 登录后两分钟 CSRF
tags:
- web
- csrf
- samesite
- lax
- chrome
- cookie-refresh
- timing
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:33:08+08:00'
  notes: 已对照原文 Lax 绕过方法 2 正文核对（该节截图均为远程未下载）：未显式 SameSite 的 Cookie 在顶级 POST 前 120 秒豁免、登录/OAuth 回调重置窗口；卡片与原文一致。PoC 未执行。
---

## 一句话结论

Chrome 为防止破坏 SSO，对“未显式设置 SameSite 的 Cookie”在顶级跨站 POST 导航后的前 120 秒内不强制执行 Lax；攻击者在受害者刚完成登录/OAuth 回调、Cookie 刚刷新的两分钟内投递自动提交的 POST 表单，即可让 Cookie 随请求发送并完成 CSRF。

## 原理

- **默认 Lax 的兼容例外**：Chrome 从 2021 年起对未声明 SameSite 的 Cookie 应用默认 Lax，但为避免新 Cookie 在跨站 SSO 回调（顶级 POST）中失效，引入了“Lax + POST”干预：Cookie 创建后的 120 秒内，顶级跨站 POST 仍会携带该 Cookie。
- **时间窗**：窗口从 Cookie 被设置/刷新时开始计算。登录、退出后重新登录、OAuth 回调、会话刷新都会重新设置会话 Cookie，从而重置窗口。
- **攻击方式**：攻击者先触发受害者的重新登录/OAuth 流程（例如诱导点击登录入口、退出再登录），然后在 2 分钟内让受害者访问自动提交 POST 表单的攻击页；此时浏览器把该跨站 POST 视为“新 Cookie 的兼容窗口”，附带会话 Cookie。
- **为什么成立**：这是浏览器为兼容性保留的行为，服务端无法感知“Cookie 是否在 120 秒内”；只要状态变更接口无 Token，窗口内即可被利用。超过 120 秒后同样的 POST 不带 Cookie，攻击失败。
- **验证要点**：在登录后立即提交跨站 POST，对比 2 分钟后再提交，观察 Cookie 是否携带；需使用未显式设置 SameSite 的 Cookie 与 Chrome 类浏览器。

## 触发条件

- 会话 Cookie 未显式设置 `SameSite`（依赖浏览器默认 Lax）。
- 使用 Chrome/Chromium 系浏览器且该干预生效。
- 状态变更接口为 POST、无 CSRF Token，且仅依赖会话 Cookie。
- 攻击者能触发受害者重新登录/会话刷新，并在 120 秒内让其访问攻击页。

## 利用步骤

1. 确认登录响应中的 `Set-Cookie` 没有 `SameSite` 属性，且修改接口为无 Token 的 POST。
2. 准备自动提交的跨站 POST 表单攻击页。
3. 诱导受害者执行一次登录/退出再登录/OAuth 回调，使会话 Cookie 刚被设置。
4. 在 2 分钟内让受害者访问攻击页，表单自动提交；浏览器在豁免窗口内附带 Cookie，服务端执行操作。
5. 若超过 2 分钟失败，重复触发登录刷新并立即重试。
6. 验证：HTTP 历史中该跨站 POST 携带了会话 Cookie；对比 2 分钟后的请求不带 Cookie。

## PoC

```html
<script>history.pushState('', '', '/')</script>
<form action="https://victim.example/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.example">
</form>
<script>document.forms[0].submit();</script>
```

投递时机：受害者完成登录/OAuth 回调后的 120 秒内。

## 变体与关联

- [[web-generic-csrf-samesite-lax-bypass-method-override]]：Lax 的另一条绕过（GET + 方法重写）。
- [[web-generic-csrf-samesite-strict-bypass-client-side-redirect]]、[[web-generic-csrf-samesite-strict-bypass-sibling-domain-cswsh]]：Strict 场景绕过。
- [[web-generic-csrf-missing-token-state-changing-endpoint]]：无 Token 基础场景（本卡依赖其成立）。
- 变体：其它浏览器/版本对默认 Lax 的兼容策略可能不同；Cookie 刷新可由 SSO、会话续期、子域登录触发。
- 边界：Cookie 显式 `SameSite=Lax/Strict/None` 时无此窗口；超过 120 秒；服务端有 CSRF Token 或 Origin 校验时链断。

## 检测与防御

- 检测：登录后短时间内的跨站 POST 请求携带会话 Cookie；无 Token 的 POST 写操作来自外部 Referer/Origin。
- 防御：对所有 Cookie 显式设置 `SameSite=Lax/Strict`（显式设置后不再享受该兼容窗口）；状态变更校验 CSRF Token 与 Origin/Referer；缩短会话 Cookie 生命周期并监控异常登录后写操作。
- 响应：排查登录后 2 分钟内的异常写请求。
