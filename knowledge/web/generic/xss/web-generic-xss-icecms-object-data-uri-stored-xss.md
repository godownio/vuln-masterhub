---
id: web-generic-xss-icecms-object-data-uri-stored-xss
title: IceCMS 广场存储型 XSS（CVE-2023-6466）：`<object data="data:text/html,...">` 绕过上一版关键字修复
type: scenario
domain: web
path: web/generic/xss
technique: icecms-object-data-uri-stored-xss
aliases:
- IceCMS 存储型 XSS
- CVE-2023-6466
- object data URI XSS
- data:text/html script
- 广场 XSS
tags:
- xss
- stored-xss
- icecms
- object
- data-uri
- filter-bypass
- java
- vue
cve:
- CVE-2023-6466
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: Thecosy IceCMS 2.0.1
verification:
  verified_by: verifier-V442
  verified_at: '2026-11-09T23:09:57+08:00'
  notes: 已对照原文与图9-11核对：/planet 广场发帖 <object data="data:text/html,<script>alert(...)</script>"> 存储后在另一浏览器访问触发弹窗；CVE-2023-6466 与图1 VulDB 记录（file /planet，Planet Handler，XSS）一致；affected_versions 2.0.1 与原文/图1（up to 2.0.1）相符。未验证点：原文文字为 alert(5) 而图10/11实际为 alert(1)，均为演示值；未复测 CSP/浏览器差异。
---

## 一句话结论

IceCMS 的 "广场" 发帖内容会原样存库并在 `/planet` 页面作为 HTML 渲染；早期版本修过一次 XSS 但过滤不完整，用 `<object data="data:text/html,<script>alert(5)</script>"></object>` 把脚本放进 data URI 子文档即可在浏览者浏览器执行，构成存储型 XSS（CVE-2023-6466）。

## 原理

- **存储路径**：登录用户在广场发帖，正文经 `/square/...` 接口入库，`/planet` 列表直接输出正文 HTML，未做输出编码或 HTML 白名单净化。
- **为什么 `<object>` 能绕过**：`<object>` 的 `data` 属性接受任意 URL，包括 `data:text/html,...`。浏览器会把 data URI 当作一个独立 HTML 文档加载到 object 内嵌浏览上下文，其中的 `<script>` 正常执行，因此不依赖页面内联 `<script>` 是否被过滤。
- **绕过点**：上一版修复只针对 `<script>` 标签或少量事件属性做黑名单，未禁止 `object`/`embed`/`iframe` 等嵌入元素与 `data:` 协议，黑名单式过滤被换载体绕过。
- **影响边界**：data: 文档运行在不透明源（opaque origin），脚本无法直接读取父页面 DOM/Cookie，因此危害弱于同源脚本注入；但仍能执行任意 JS、做弹窗钓鱼、跳转、探测浏览器环境，结合浏览器特性或后续漏洞可放大。
- **判定**：换浏览器/换会话重新访问 `/planet` 时弹窗仍触发，说明 payload 已持久化在服务端而非仅本地渲染。

## 触发条件

- 目标为 IceCMS 2.0.1（CVE-2023-6466）。
- 攻击者拥有可发帖的普通账号（广场允许登录用户发布内容）。
- 受害者（可以是管理员或其他用户）访问 `/planet` 广场列表页。
- 站点未配置禁止 object/data: 的 CSP（如 `object-src 'none'`），或浏览器版本允许 object 加载 data: 文档。

## 利用步骤

1. 注册/登录普通账号，进入 `/planet` 广场。
2. 在发帖编辑框提交 payload：`<object data="data:text/html,<script>alert(5)</script>"></object>`。
3. 发布后用另一浏览器/未登录会话访问 `/planet`，确认弹窗执行。
4. 实战化可替换为更完整的 data: HTML 文档（钓鱼表单、跳转、探测），或尝试其他嵌入标签与编码变体绕过更新后的过滤。

## PoC

```html
<object data="data:text/html,<script>alert(5)</script>"></object>
```

存库后访问 `/planet` 即触发 `alert(5)`。注意 data: 文档为不透明源，脚本读不到本站 Cookie/DOM，弹窗仅证明脚本执行。

## 变体与关联

- 变体：`<iframe src="data:text/html,...">`、`<embed src="data:text/html,...">`；若 `data:` 被拦可尝试 `javascript:` 伪协议或 SVG 事件载体。
- 变体：若正文过滤 `<script>` 但允许事件属性，可改用 `<img src=x onerror=...>`（见 scriptless XSS 通用卡）。
- 关联：[[web-generic-xss-scriptless-execution-vectors]]（script 被过滤时的替代载体）；[[web-generic-xss-data-iframe-postmessage-innerhtml]]（data: iframe 与 postMessage 组合）。

## 检测与防御

- 检测：发帖内容中出现 `object`/`embed`/`iframe`/`data:`/`javascript:` 等危险标签或协议；存储内容与页面输出存在未编码 HTML。
- 防御：输出按上下文做 HTML 编码；使用 HTML 白名单 sanitizer（如 OWASP Java HTML Sanitizer）而非黑名单；CSP 配置 `object-src 'none'`、`frame-src` 白名单；对用户内容做服务端二次过滤。
- 局限：客户端 data: 源隔离降低了直接会话窃取风险，但脚本执行本身仍是 XSS 缺陷，不应因当前影响有限而忽略。
