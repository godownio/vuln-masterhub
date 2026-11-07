---
id: web-php-warning-header-already-sent-csp-bypass
title: PHP Warning 提前输出导致 CSP 响应头失效
type: scenario
domain: web
path: web/php
technique: php-warning-headers-already-sent-csp-bypass
tags:
- php
- csp
- xss
- header
- warning
- max-input-vars
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V14
  verified_at: '2026-11-05T01:39:03+08:00'
  notes: 已对照原文pilvar示例图核对；请求启动期warning->headers already sent->CSP未下发链条一致；PHP8.3.6/Apache为示例环境；未实机复现；已在卡内区分代理层CSP不受影响
url: /docs/web/php/web-php-warning-header-already-sent-csp-bypass/
draft: false
kb_aliases:
- headers already sent 绕过 CSP
- PHP warning CSP bypass
- max_input_vars 触发 warning
- Cannot modify header information
- CSP header 未发送
---

## 一句话结论

PHP 在第一次输出时就会发送响应头；如果攻击者能先触发一个 PHP Warning（例如让 GET/POST 参数超过 `max_input_vars`），警告内容先进入响应体，后续 `header("Content-Security-Policy: ...")` 就会因 headers already sent 而失败，CSP 响应头根本不会下发，页面里的 XSS 得以执行。

## 原理

- PHP 的响应头在首次输出（echo、警告、错误信息等）时随响应体一起发送。之后再调用 `header()` 只会产生 “Cannot modify header information - headers already sent” 警告，目标头不会写入响应。
- PHP 在处理请求启动阶段有输入数量上限：默认 `max_input_vars=1000`，GET/POST 参数超过上限会发出 “PHP Request Startup: Input variables exceeded 1000” 警告并截断后续参数；文件上传超过 20 个也会告警。这些警告发生在应用代码执行之前，输出直接进入响应体。
- 因此若应用把安全头放在业务逻辑里通过 `header()` 设置，而攻击者能先触发上述警告，CSP 就不会出现在响应头里；浏览器没有策略可执行，原本被 CSP 拦住的 `<script>` 标签或内联脚本可以运行。
- 该技巧不依赖 PHP 版本漏洞，只利用“输出先于 header”和可触发的 warning，属于逻辑/时序问题。

## 触发条件

- 应用在可能产生输出的代码之后调用 `header()` 设置 CSP 等安全头，或安全头只在部分分支设置。
- `display_errors` 开启，警告会回显到响应体（生产环境常见误配）。
- 攻击者能控制请求参数数量，触发 `max_input_vars` 超限或其他早期 warning。
- 页面存在 XSS 注入点，且该 XSS 原本仅被 CSP 阻止。

## 利用步骤

1. 确认目标响应头中没有 CSP，或 CSP 由 PHP 动态设置；观察正常请求是否带头。
2. 构造请求：放入 XSS payload，并追加大量重复参数（GET 约 1000 个以上）触发 warning。
3. 观察响应体是否以 PHP Warning 开头，且响应头中缺少 CSP。
4. 浏览器解析到脚本并执行，验证 XSS。

## PoC

```http
GET /?xss=<script>alert(1)</script>&a&a&a...（重复约 1000 个 a） HTTP/1.1
Host: target
```

对应最小应用：

```php
<?php
header("Content-Security-Policy: default-src 'none';");
if (isset($_GET["xss"])) echo $_GET["xss"];
```

响应体开头出现：

```html
<br /><b>Warning</b>: PHP Request Startup: Input variables exceeded 1000. ...
<br /><b>Warning</b>: Cannot modify header information - headers already sent ...
<script>alert(1)</script>
```

由于 CSP 头未发送，脚本执行。

## 变体与关联

- 变体：POST 参数超过 1000、文件上传超过 20 个、或其他在 `header()` 前产生的 warning/notice 都可触发同样的“头已发送”。
- 变体：若 CSP 由反向代理统一添加（如 Caddy），PHP warning 不影响 CSP，只能用于把响应推入怪异模式（见 [[web-generic-xs-leaks-css-pattern-valid-frame-counting-token]]）。
- 关联：[[web-generic-xs-leaks-css-pattern-valid-frame-counting-token]]（同一 warning 技巧的另一种后果）。
- 边界：`display_errors=Off` 时警告不输出，PHP 不会因此提前发送响应体；安全头在 Web 服务器/代理层设置时不受影响。

## 检测与防御

- 检测：响应体在 doctype 前出现 `Warning`/`Notice`；响应头缺失预期的 CSP；单请求参数数量异常多。
- 防御：生产环境关闭 `display_errors`，错误写入日志；在应用入口最前面设置安全头，或用输出缓冲（`ob_start`）确保头先发送。
- 加固：安全头在 Nginx/Apache/Caddy 等反向代理层统一添加，不依赖 PHP `header()`；限制单请求参数数量并对异常请求告警。
