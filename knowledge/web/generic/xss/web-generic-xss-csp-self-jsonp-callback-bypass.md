---
id: web-generic-xss-csp-self-jsonp-callback-bypass
title: CSP script-src 'self' 下通过同源 JSONP 回调注入执行任意 JS
type: scenario
domain: web
path: web/generic/xss
technique: csp-jsonp-callback-bypass
aliases:
- JSONP 绕过 CSP
- script-src self 绕过
- CSP 同源脚本绕过
- callback 参数注入
tags:
- xss
- csp
- jsonp
- bypass
- script-src
- same-origin
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:49:57+08:00'
  notes: 已对照原文核对：CSP script-src 'self' 禁 inline、同源 JSONP callback 原样拼接、<script src="?callback=alert(1)"> 绕过均与原文一致；未实际执行
---

## 一句话结论

当 CSP 配置为 `script-src 'self'`（只允许同源脚本、禁止内联）时，若同源存在把 `callback` 参数原样拼进 JavaScript 响应的 JSONP 端点，攻击者注入 `<script src="?callback=alert(1)"></script>` 就能借同源白名单加载并执行任意 JS，CSP 形同虚设。

## 原理

- `script-src 'self'` 的语义是：只允许加载与文档同源的脚本 URL，内联 `<script>...</script>` 与 `eval` 被禁止。很多部署因此认为“即使有 HTML 注入也无法执行脚本”。
- 但 CSP 限制的是**脚本的来源**，不是脚本**内容**。同源服务器上任何返回 `application/javascript` 且内容部分可控的端点，都会被当作合法脚本执行。
- JSONP 端点典型实现是 `echo $cb . '({"status":"ok",...});'`。`$cb` 来自 `?callback=`，没有做标识符白名单校验。请求 `?callback=alert(1)` 时响应体为 `alert(1)({"status":"ok",...});`：浏览器先执行 `alert(1)`（返回 `undefined`），随后 `undefined({...})` 抛错，但代码已经执行。
- 攻击者要做的只是让页面加载该脚本：注入 `<script src="/api?callback=alert(1)"></script>`。该 URL 同源，符合 `script-src 'self'`，CSP 不拦截；内联脚本限制也被绕过（外部脚本不是 inline）。
- 根因：CSP 的 `'self'` 把“同源所有脚本端点”都纳入信任边界，而 JSONP 让攻击者控制脚本内容，等于把 XSS 变成“合法同源脚本”。

## 触发条件

- 页面存在任意 HTML 注入点（能插入 `<script src=...>` 标签），但 CSP 阻止内联脚本；
- 同源存在 JSONP/回调式端点，`callback`、`jsonp`、`cb` 等参数被原样写入响应且 `Content-Type` 为 JS；
- 端点无需认证，或攻击者可用受害者会话访问；
- CSP 未额外使用 nonce/hash 或 `strict-dynamic` 限制脚本。

## 利用步骤

1. 读取响应头确认 CSP：`script-src 'self'` 且无 nonce/hash。
2. 在页面源码/接口文档中寻找 JSONP 端点（`?callback=test` 之类的调试链接、旧 API）。
3. 用 `?callback=alert(1)` 请求，确认响应体以 `alert(1)(` 开头且 `Content-Type` 为 JS。
4. 在 HTML 注入点插入 `<script src="<jsonp-url>?callback=alert(document.cookie)"></script>`。
5. 访问页面，脚本以同源身份加载执行；用 `fetch` 外带 cookie 验证真实危害。

## PoC

```html
<!-- 注入点（HTML 上下文） -->
<script src="/api/jsonp?callback=alert(document.cookie)"></script>
```

```text
# 服务端响应
Content-Type: application/javascript

alert(document.cookie)({"status":"ok","time":"2026-01-01 00:00:00"});
```

```php
// 有漏洞的 JSONP 端点
if (isset($_GET['callback'])) {
    header('Content-Type: application/javascript');
    echo $_GET['callback'] . '({"status":"ok"});';
    exit;
}
```

## 变体与关联

- 变体：`callback=alert(1)//` 可注释掉尾部 JSON，避免报错；`callback=while(1){}//`（DoS，不建卡）等。
- 变体：CSP 允许 `https:` 或 CDN 域名时，可利用同域/白名单域名上的 JSONP 端点（如旧版 jQuery/Google API）。
- 变体：AngularJS 等库的 JSONP 机制、`document.domain` 放宽后的跨子域脚本同样可被滥用。
- 关联：[[web-generic-xss-angularjs-sandbox-escape]]（CSP 允许 unsafe-eval 时的表达式执行）；[[web-generic-xss-data-iframe-postmessage-innerhtml]]（CSP 的 frame-src 视角）。

## 检测与防御

- 检测：CSP 为 `script-src 'self'` 但站点存在 `callback=`/`jsonp=` 端点；响应中出现未加引号的回调名直接拼接。
- 检测：页面中出现指向同源 JSONP 端点的 `<script src>`，特别是 `callback` 内含 `alert`、`fetch`、`document.cookie` 等。
- 防御：移除 JSONP，改用 CORS + `fetch`；必须保留时对 `callback` 做严格正则白名单（`^[a-zA-Z_$][a-zA-Z0-9_$.]*$`），并禁止 `(`、`)`、`.` 等可执行字符。
- 防御：CSP 使用 nonce/hash 或 `strict-dynamic`，避免 `'self'` 成为可滥用的信任源；同时设置 `object-src 'none'`、`base-uri 'none'`。
- 防御：为 JSONP 响应加 `X-Content-Type-Options: nosniff`，但这不能阻止作为 script 加载，核心仍是消除回调注入。
