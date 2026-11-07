---
id: web-generic-xss-path-segment-reflected-svg
title: 路径段原样回显导致反射型 XSS（SVG onload）
type: scenario
domain: web
path: web/generic/xss
technique: path-segment-reflected-xss
aliases:
- 路径反射 XSS
- URL 路径 XSS
- path 段回显 XSS
- SVG onload 反射型 XSS
- 路由参数反射
tags:
- web
- xss
- reflected-xss
- path
- svg
- url-encoding
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V75
  verified_at: '2026-11-05T16:51:17+08:00'
  notes: 已对照图07核对；/public/page/%3Csvg%20onload%3Dalert(1)%3E 触发弹窗，路径段回显XSS成立；PoC未复跑
---

## 一句话结论

当 Web 应用把 URL 路径中的一段直接拼进 HTML 响应、未做输出编码时，攻击者可构造包含 HTML 标签的路径，浏览器解析后执行脚本；用 `<svg onload=alert(1)>` 可无需用户交互即触发。

## 原理

- 路径参数与查询参数一样来自用户输入。路由/页面渲染若把 `path` 段原样写入响应（如 `Page: /<path>`、错误页回显请求路径、面包屑导航），就形成反射型 XSS 的注入点。
- URL 中的 `%3C`、`%3E`、`%22` 等百分号编码在被服务端/框架解码后还原为 `<`、`>`、`"`；若随后直接拼接进 HTML 文本节点，浏览器会按标签解析。
- `<svg onload=...>` 是常见的无交互 payload：SVG 元素加载完成后自动触发 `onload`，不依赖用户点击；对只过滤 `<script>` 的场景尤其有效。
- 该漏洞通常不依赖登录（路径可匿名访问），影响包括会话劫持、钓鱼、前端操作代执行；若站点存在 HttpOnly 之外的敏感数据或 CSRF 弱点，可进一步组合。
- 与 DOM XSS 的区别：本例是服务端把路径回显到 HTML（反射型）；若路径只被前端 JS 读取并写入 `innerHTML`，则归入 DOM XSS。

## 触发条件

- 应用使用路径段作为页面参数/路由参数，并在响应中原样回显；
- 回显位置处于 HTML 文本或属性上下文，未做 HTML 实体编码；
- 浏览器未启用可阻断内联脚本的严格 CSP（或 CSP 允许 `unsafe-inline`/对应来源）；
- 目标页面可被受害者访问，攻击者能构造并投递 URL。

## 利用步骤

1. 找到使用路径段渲染的页面，例如 `/public/page/<name>`、`/error/<path>`、`/search/<keyword>`。
2. 在路径段放入无害标记（如 `test<b>1</b>`）观察是否被解析为 HTML，确认回显点与上下文。
3. 构造 URL 编码的 SVG payload：`%3Csvg%20onload%3Dalert(1)%3E`，替换路径段后访问。
4. 观察是否弹窗；若被过滤，尝试大小写、双重编码、事件属性变体或其它无交互标签。
5. 在授权范围内将 PoC 收敛为最小 payload，并记录触发页面、注入上下文与浏览器行为。

## PoC

```text
https://target.example.com/public/page/%3Csvg%20onload%3Dalert(1)%3E
```

解码后的路径段为：

```html
<svg onload=alert(1)>
```

若回显在 HTML 文本中，页面加载后自动执行 `alert(1)`；原文即用该 payload 验证路径拼接 XSS。

## 变体与关联

- 变体：路径段回显到属性上下文时，使用 `"` 闭合属性并注入事件；回显到 `<script>` 字符串时改用 JS 字符串闭合。
- 变体：双重 URL 编码、`;` 矩阵参数、路径归一化差异可绕过简单过滤或 WAF。
- 关联：[[web-generic-xss-scriptless-execution-vectors]]（SVG/事件处理器等替代执行载体）、[[web-generic-xss-filter-bypass-encoding-obfuscation]]（编码与黑名单绕过）。
- 边界：服务端对路径做 HTML 实体编码、框架默认转义、严格 CSP 禁止内联脚本时，payload 不执行。

## 检测与防御

- 检测：路径段中出现 `%3C`、`%3E`、`onload`、`onerror`、`<svg` 等模式；响应中路径与请求路径一致且含 HTML 标签；WAF/日志中的异常路径 payload。
- 防御：对回显到 HTML 的任何用户输入做上下文相关的输出编码（HTML 实体编码、属性编码、JS 编码）；优先使用模板引擎的自动转义。
- 防御：部署严格 CSP（禁止 `unsafe-inline`，限制脚本来源），作为纵深防御；对路径参数做长度/字符白名单校验。
- 防御：错误页与面包屑不要原样回显完整 URL；使用固定文案或安全编码后的路径。
