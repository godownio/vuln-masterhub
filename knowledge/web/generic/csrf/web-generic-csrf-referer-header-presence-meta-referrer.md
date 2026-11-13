---
id: web-generic-csrf-referer-header-presence-meta-referrer
title: Referer 校验依赖请求头存在：用 meta referrer=no-referrer 丢弃 Referer 绕过
type: scenario
domain: web
path: web/generic/csrf
technique: csrf-referer-presence-meta-no-referrer
aliases:
- Referer 绕过 CSRF
- meta referrer no-referrer
- 删除 Referer 头
- referer validation depends on header being present
tags:
- web
- csrf
- referer
- referrer-policy
- meta
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V606
  verified_at: '2026-11-12T18:33:10+08:00'
  notes: 已对照原文 Referer 绕过方式 1 正文核对（该节截图均为远程未下载）：改/删 Referer 测试、meta referrer=no-referrer 丢弃 Referer 通过校验；原文代码块写作 never，实际 PoC 与卡片使用 no-referrer 正确。PoC 未执行。
---

## 一句话结论

当应用只在请求带 Referer 头时才校验其来源、Referer 缺失时直接放行，攻击者可在承载 CSRF 表单的页面里加 `<meta name="referrer" content="no-referrer">`，让浏览器自动提交的请求不带 Referer，从而跳过校验。

## 原理

- **存在性判断缺陷**：典型代码为 `String referer = request.getHeader("Referer"); if (referer != null && !referer.startsWith("https://victim.example")) reject();`——`null` 时条件短路，请求被放行。Referer 是可选请求头，服务端不能假设它一定存在。
- **浏览器如何省略 Referer**：页面可通过 `Referrer-Policy` 控制后续请求的 Referer。`<meta name="referrer" content="no-referrer">` 对整页生效，页面发起的表单提交/跳转都不带 Referer；等价响应头为 `Referrer-Policy: no-referrer`。
- **为什么成立**：CSRF 防护若把“缺失 Referer”当作可信，等于允许攻击者主动丢弃该头；浏览器隐私设置、代理、HTTPS→HTTP 降级等也会造成 Referer 缺失，因此正确策略应是“缺失即拒绝”，或改用 CSRF Token。
- **验证要点**：正常请求改/删 Referer，确认删除后仍成功；攻击页加 meta 后提交，确认请求头中 Referer 不存在。

## 触发条件

- 目标使用 Referer 头做 CSRF 校验，且逻辑为“存在才校验、缺失放行”。
- 状态变更接口无 CSRF Token 或 Token 可绕过。
- 受害者的浏览器支持并遵守 `no-referrer` 策略（主流浏览器均支持）。
- 攻击请求能携带受害者 Cookie（Lax/None 或顶级导航）。

## 利用步骤

1. 抓取正常修改请求，把 Referer 改成其它域，确认被拒绝（Invalid referer header）。
2. 完全删除 Referer 头重放，确认请求被接受并完成修改。
3. 构造攻击页：`<meta name="referrer" content="no-referrer">` + 自动提交表单。
4. 托管并投递给受害者；浏览器提交表单时不发送 Referer，服务端跳过校验。
5. 验证：受害者数据被修改；抓包确认请求无 Referer 头。

## PoC

```html
<html>
  <head>
    <meta name="referrer" content="no-referrer">
  </head>
  <body>
    <form action="https://victim.example/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.example">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

## 变体与关联

- [[web-generic-csrf-referer-weak-validation-subdomain-query-unsafe-url]]：Referer 校验过于宽松（前缀/包含）的另一类绕过。
- [[web-generic-csrf-missing-token-state-changing-endpoint]]：无 Token 基础。
- 变体：用响应头 `Referrer-Policy: no-referrer`、`same-origin` 或 `<a rel="noreferrer">` 丢弃 Referer；不同策略组合产生的 Referer 粒度不同。
- 边界：服务端把“Referer 缺失”视为拒绝、或用 CSRF Token/Origin 校验时链断。

## 检测与防御

- 检测：Referer 校验代码中存在 `referer != null` 短路；缺少 Referer 的写请求成功。
- 防御：Referer/Origin 校验采用默认拒绝（缺失即拒绝），并使用 CSRF Token 作为主防御；不要依赖 Referer 单独防护；校验时解析为 URL 后比较 host。
- 响应：排查无 Referer 的异常写请求。
