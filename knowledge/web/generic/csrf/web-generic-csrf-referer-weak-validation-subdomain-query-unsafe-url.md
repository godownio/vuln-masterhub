---
id: web-generic-csrf-referer-weak-validation-subdomain-query-unsafe-url
title: Referer 弱校验绕过：攻击者子域或 URL query 携带目标域名 + unsafe-url 策略
type: scenario
domain: web
path: web/generic/csrf
technique: csrf-referer-weak-validation-bypass
aliases:
- Referer 前缀绕过
- Referer 包含匹配绕过
- Referrer-Policy unsafe-url
- 子域伪装 Referer
- broken referer validation
tags:
- web
- csrf
- referer
- referrer-policy
- subdomain
- url-parsing
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:33:12+08:00'
  notes: '已对照原文 Referer 绕过方式 2 正文核对（该节截图均为远程未下载）：contains 校验、URL query 含目标域名 + Referrer-Policy: unsafe-url、history.pushState 载荷；卡片与原文一致。PoC 未执行。'
---

## 一句话结论

当应用只用 `startsWith`/`contains` 简单判断 Referer 是否包含目标域名时，攻击者可以把攻击页放在 `victim.example.attacker.example` 这类以目标域开头的域名下，或在攻击 URL 的 query 中写入 `victim.example`，再配合 `Referrer-Policy: unsafe-url` 让完整 URL 进入 Referer，从而通过校验完成 CSRF。

## 原理

- **前缀校验**：`referer.startsWith("https://victim.example")` 会把 `https://victim.example.attacker.example/csrf` 判定为可信，因为字符串确实以 `https://victim.example` 开头；攻击者只需注册一个以目标域为子域前缀的域名。
- **包含校验**：`referer.contains("victim.example")` 会把 `https://attacker.example/csrf?victim.example` 判定为可信；攻击者在自己的 URL 任意位置放入目标域名即可。
- **Referrer-Policy 的作用**：跨站请求默认策略（如 `strict-origin-when-cross-origin`）只发送源（scheme+host+port），不带路径和 query；要让 query 中的目标域出现在 Referer，需要把攻击页策略设为 `unsafe-url`（响应头或 `<meta name="referrer" content="unsafe-url">`），此时完整 URL 作为 Referer 发送。
- **为什么成立**：Referer 校验必须把值解析成 URL 后比较 `host`（并考虑端口/scheme），而不是做字符串匹配；字符串包含关系可被攻击者完全控制。
- **验证要点**：分别用“前缀伪装域”“query 含目标域”“Referer 策略 unsafe-url”测试，确认服务端只做字符串匹配。

## 触发条件

- 目标使用 Referer 头做 CSRF 校验，且实现为 `startsWith`/`contains` 等字符串匹配。
- 攻击者可注册/控制一个以目标域为前缀的域名，或可让攻击 URL 的 query 包含目标域名。
- 状态变更接口无 CSRF Token 或 Token 可绕过。
- 浏览器允许攻击页通过 `Referrer-Policy: unsafe-url` 发送完整 Referer。

## 利用步骤

1. 抓取正常请求，确认 Referer 原始域可通过；改成其它域/删除均被拒。
2. 测试校验方式：把 Referer 改成 `https://victim.example.attacker.example/`，若通过则为前缀匹配；改成 `https://attacker.example/?victim.example`，若通过则为包含匹配。
3. 前缀场景：在 `victim.example.attacker.example` 托管攻击页；包含场景：在攻击 URL 后加 `?victim.example` 并用 `history.pushState` 把地址栏改为该路径。
4. 在攻击页设置 `Referrer-Policy: unsafe-url`（响应头或 meta），使完整 URL 作为 Referer。
5. 自动提交表单；服务端字符串匹配通过，执行状态变更。
6. 验证：请求 Referer 为攻击者 URL 且包含目标字符串；数据被修改。

## PoC

```html
<html>
  <head>
    <meta name="referrer" content="unsafe-url">
  </head>
  <body>
    <script>history.pushState('', '', '/?victim.example')</script>
    <form action="https://victim.example/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.example">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

若为前缀匹配，则将攻击页托管在 `https://victim.example.attacker.example/` 并直接提交表单。

## 变体与关联

- [[web-generic-csrf-referer-header-presence-meta-referrer]]：Referer 缺失即放行的另一类缺陷。
- [[web-generic-csrf-missing-token-state-changing-endpoint]]：无 Token 基础。
- 关联 open-redirect/子域接管卡片：用于取得以目标域为前缀的域名或站内跳转。
- 变体：`endsWith`/正则未锚定、未解析 URL、未校验端口/scheme、`Referer` 大小写与编码差异。
- 边界：服务端解析 URL 后严格比较 host、使用 CSRF Token/Origin 校验、攻击者无法取得匹配域名或控制 policy 时链断。

## 检测与防御

- 检测：Referer 校验代码做字符串 `startsWith`/`contains`；日志中出现 Referer host 为目标子域前缀或 query 含目标域的写请求。
- 防御：把 Referer/Origin 解析为 URL 后严格比较 scheme+host+port，采用白名单与默认拒绝；以 CSRF Token 为主防御；不要依赖 Referer 单独防护。
- 响应：排查 Referer 异常但成功的写请求，评估是否被利用。
