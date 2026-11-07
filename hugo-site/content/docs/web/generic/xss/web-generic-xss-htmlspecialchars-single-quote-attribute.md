---
id: web-generic-xss-htmlspecialchars-single-quote-attribute
title: htmlspecialchars 默认 flags 未转义单引号导致单引号属性上下文 XSS
type: scenario
domain: web
path: web/generic/xss
technique: xss-htmlspecialchars-quote-context
affected_versions: PHP < 8.1.0（htmlspecialchars 默认 flags 为 ENT_COMPAT | ENT_HTML401）
tags:
- xss
- php
- htmlspecialchars
- output-encoding
- attribute-context
- event-handler
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:39:25+08:00'
  notes: 已对照原文核对：PHP <8.1.0 默认 flags 不转义单引号、单引号属性上下文 onmouseover 闭合、8.1.0 起 ENT_QUOTES 修复，均与原文 level3 描述一致；affected_versions 已正确设置。原文无图片。PoC 未独立执行。
url: /docs/web/generic/xss/web-generic-xss-htmlspecialchars-single-quote-attribute/
draft: false
kb_aliases:
- htmlspecialchars 单引号绕过
- PHP htmlspecialchars XSS
- 单引号属性闭合 XSS
- ENT_COMPAT 绕过
---

## 一句话结论

PHP 8.1.0 之前 `htmlspecialchars()` 的默认 flags 是 `ENT_COMPAT | ENT_HTML401`，只转义双引号而不转义单引号；如果应用把用户输入输出到单引号包裹的 HTML 属性中，攻击者可以用一个 `'` 闭合属性并注入事件处理器，从而执行 JavaScript。

## 原理

- `htmlspecialchars()` 的转义范围由第二个参数 `flags` 决定，默认值在 PHP 8.1.0 之前是 `ENT_COMPAT | ENT_HTML401`：
  - 转义 `<`、`>`、`&`、`"`；
  - **不转义** `'`。
- HTML 属性可以用单引号或双引号包裹。若模板写成 `<input value='USER_INPUT'>`，输入中的 `'` 会提前闭合 `value` 属性，后面的内容被解析为新的属性。
- 事件处理器属性（`onmouseover`、`onfocus`、`onerror`、`onload` 等）是合法的 HTML 属性，浏览器在对应事件触发时执行其 JavaScript；不需要 `<script>` 标签。
- 因此 `' onmouseover=alert(1) x='` 会生成 `<input value='' onmouseover=alert(1) x=''>`，鼠标移入输入框即执行。
- PHP 8.1.0 起默认 flags 改为 `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401`，单引号也会被转义，这一具体绕过失效；但 `htmlspecialchars` 本身仍不能替代上下文相关的输出编码（例如 JavaScript、URL、CSS 上下文）。

## 触发条件

- PHP 版本低于 8.1.0，或显式使用了 `ENT_COMPAT`/未包含 `ENT_QUOTES` 的 flags。
- 用户输入被输出到单引号包裹的 HTML 属性值中。
- 输出前只调用了 `htmlspecialchars()`，没有额外的引号/属性白名单过滤。
- 页面没有 CSP 阻止内联事件处理器（或 CSP 允许 `unsafe-inline`）。

## 利用步骤

1. 找到反射/存储型输入点，确认输入出现在单引号属性中，例如 `value='...'`。
2. 提交 `' onmouseover=alert(1) x='`，观察响应中单引号是否原样保留。
3. 若 `onmouseover` 被过滤，换 `onfocus` + `autofocus`、`onclick`、`onerror` 等事件。
4. 若 `alert` 被过滤，用 `confirm`、`print`、`prompt` 或编码后的等价调用验证。
5. 验证触发：鼠标移入/点击/自动聚焦时执行；无需 `<script>` 标签。

## PoC

```html
<!-- 服务端模板：<input value='<?= htmlspecialchars($_GET['q']) ?>'> -->
<!-- 请求：?q=' onmouseover=alert(1) x=' -->
<input value='' onmouseover=alert(1) x=''>
```

```html
<!-- 自动触发变体 -->
<input value='' autofocus onfocus=alert(1) x=''>
```

说明：PoC 依赖 PHP < 8.1.0 的默认 flags 与单引号属性上下文；未在目标环境执行。

## 变体与关联

- 变体：显式传入 `ENT_COMPAT` 或 `ENT_NOQUOTES` 时，即使 PHP 8.1+ 也可能不转义单引号/双引号，需按实际 flags 判断。
- 变体：输出在无引号属性、`href`/`src` URL、`<script>` 字符串或 CSS 上下文时，`htmlspecialchars` 的防护同样不完整，需要对应的上下文编码。
- 关联：[[web-generic-xss-filter-bypass-encoding-obfuscation]]（字符黑名单/替换过滤的其他绕过）；[[web-generic-xss-scriptless-execution-vectors]]（无 `<script>` 标签时的执行载体，含 HTML 实体与 `javascript:` 伪协议组合）。

## 检测与防御

- 检测：代码审计中搜索 `htmlspecialchars(` 未显式传 `ENT_QUOTES` 的调用；模板中单引号包裹属性且拼接用户输入。
- 检测：请求参数中出现 `' on...=`、`" on...=`、`autofocus onfocus` 等属性注入特征；响应中出现未转义的单引号闭合。
- 防御：显式使用 `htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`；升级 PHP 到 8.1.0+。
- 防御：按输出上下文选择编码（HTML 属性、JavaScript、URL、CSS 分别处理）；属性值统一用双引号并由模板引擎自动转义。
- 防御：部署 CSP，禁止 `unsafe-inline`，使用 nonce/hash；对富文本使用白名单 sanitizer（如 HTMLPurifier、DOMPurify）。
