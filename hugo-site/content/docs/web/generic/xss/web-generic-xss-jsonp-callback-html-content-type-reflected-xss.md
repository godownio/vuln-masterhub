---
id: web-generic-xss-jsonp-callback-html-content-type-reflected-xss
title: JSONP 回调参数可控且响应为 text/html：callback 注入 SVG 事件形成反射 XSS
type: scenario
domain: web
path: web/generic/xss
technique: jsonp-callback-html-content-type-reflected-xss
tags:
- xss
- jsonp
- callback
- reflected
- content-type
- web
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V288
  verified_at: '2026-11-08T05:27:19+08:00'
  notes: '已对照全文与43图核对：图16 Burp JSONP Hunter加载；图17响应200 Content-Type: text/html;charset=utf-8；图18请求callback=hello<svg onload=alert(1)>、响应体回显hello<svg onload=alert(1)>({...})；图19 JSONP-Hunter仓库。卡片两条件、payload与原理一致。dedup仅与路径反射SVG/CSP JSONP卡related，非同链；dup-scan无本篇pair。未复现。'
url: /docs/web/generic/xss/web-generic-xss-jsonp-callback-html-content-type-reflected-xss/
draft: false
kb_aliases:
- JSONP XSS
- callback 参数 XSS
- jsonp 反射型 XSS
- Content-Type text/html JSONP
- JSONP-Hunter
- callback 注入
---

## 一句话结论

当 JSONP 接口把 `callback`（或 `cb`、`jsonp`）参数原样拼进响应体，且响应 `Content-Type` 为 `text/html` 时，把参数改成 `hello<svg onload=alert(1)>` 会让浏览器把响应当 HTML 解析并执行事件处理器，形成目标域下的反射型 XSS；即使响应类型是 JS，未做标识符白名单的回调参数也可被注入任意 JS 表达式。

## 原理

- JSONP 的历史实现是：页面动态插入 `<script src="https://api.example/data?callback=fn">`，服务端返回 `fn({"data":...})`，浏览器把响应当脚本执行，从而跨域取得数据。`callback` 参数因此必须是“可执行的 JavaScript 标识符/表达式”。
- 如果服务端直接把 `callback` 拼进响应而不做白名单校验，攻击者就能控制响应内容。文章的条件是两条同时成立：
  1. 响应 `Content-Type: text/html`；
  2. GET 或 POST 中的 `callback` 参数可控。
- 在 `text/html` 下，响应体不再只被当作脚本，而是被浏览器当作文档解析。payload `hello<svg onload=alert(1)>` 中的 `<svg onload=...>` 是合法的 HTML 事件处理器，页面渲染时立即执行，前面的 `hello` 与后面的 JSON 数据只是普通文本，不影响触发。
- 如果响应类型是 `application/javascript`，`<svg>` 标签不会按 HTML 渲染，但回调参数仍可注入 JS 表达式，例如 `callback=alert(1)//`，在 `<script src>` 加载时执行。是否为 XSS 取决于调用上下文和 CSP，但“回调参数未校验”始终是根因。
- 危害：脚本在目标域 origin 下执行，可读取非 HttpOnly Cookie、localStorage/sessionStorage、页面 DOM 与 CSRF token，并以受害者身份发起请求；也可用于钓鱼或跳转。
- 文章用 Burp 插件 JSONP-Hunter 自动发现带 callback 参数的 JSONP 端点，再手工验证响应类型与回调反射。

## 触发条件

- 目标存在 JSONP/回调式接口，`callback`、`cb`、`jsonp`、`jsonpcallback` 等参数被原样写入响应。
- 响应头为 `Content-Type: text/html`（或浏览器会对该响应做 HTML 解析），且没有 `Content-Disposition: attachment`。
- 服务端未对 callback 做严格标识符白名单（`^[A-Za-z_$][A-Za-z0-9_$.]*$`）。
- 页面/响应没有禁止内联事件处理器的 CSP；存在 `unsafe-inline` 或未配置 CSP 时可直接触发。
- 攻击者能让受害者访问构造好的 URL（链接、iframe、二维码、短链等）。

## 利用步骤

1. 在页面源码、JS bundle、接口文档中搜索 `callback=`、`cb=`、`jsonp=`、`jsonpcallback=`；或用 JSONP-Hunter 对目标流量做被动/主动扫描。
2. 用正常值请求一次，确认响应形如 `fn({...})`，记录参数名与响应 `Content-Type`。
3. 把回调值改为 `hello<svg onload=alert(1)>`，观察响应体是否原样回显、`Content-Type` 是否为 `text/html`。
4. 若响应为 `text/html`，直接访问构造 URL 或在 iframe 中加载，确认弹窗；若响应为 JS，改为 `callback=alert(1)//` 并用 `<script src>` 方式验证。
5. 验证真实危害：读取 `document.cookie`、`localStorage`，或发起带凭据的请求；不要对非授权目标执行。

## PoC

```http
GET /api/list?callback=hello%3Csvg%20onload%3Dalert(1)%3E HTTP/1.1
Host: target.example
Accept: text/html
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

hello<svg onload=alert(1)>({"pageCount":1,"list":[...]})
```

```http
POST /api/list HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded

callback=hello<svg onload=alert(1)>
```

## 变体与关联

- **`application/javascript` 响应**：`callback=alert(1)//` 或 `callback=alert(document.domain)//` 可在脚本上下文执行；与 `text/html` 的 HTML 解析路径不同，但根因同为回调未校验。
- **CSP `script-src 'self'` 场景**：同源 JSONP 端点可被当作合法脚本加载，绕过 CSP；已有 [[web-generic-xss-csp-self-jsonp-callback-bypass]] 覆盖该变体，本卡聚焦“回调反射 + text/html”直接 XSS。
- **JSONP 数据劫持**：即使不能执行脚本，未校验的回调也可配合攻击者页面读取跨域数据（JSON hijacking），属于另一类风险。
- 关联：[[web-generic-xss-data-exfiltration-jsonp-image-beacon-multi-channel]]（XSS 后经 JSONP/图片信标外带数据）。

## 检测与防御

- 对 callback 参数实施严格白名单：只允许合法 JavaScript 标识符与点号（如 `^[A-Za-z_$][A-Za-z0-9_$.]{0,63}$`），拒绝 `<`、`>`、`(`、`)`、`;`、`/` 等字符。
- 逐步淘汰 JSONP：改用 CORS + `application/json`，避免把数据包装成可执行脚本。
- 所有接口显式设置 `Content-Type: application/json; charset=utf-8` 与 `X-Content-Type-Options: nosniff`，避免浏览器把 JSON 当 HTML 解析。
- 配置 CSP（`default-src 'self'`、禁止 `unsafe-inline`），对反射型注入增加兜底。
- 检测：请求参数中出现 `<svg`、`onload`、`alert(`、`javascript:` 等特征；响应体在 `text/html` 下包含未转义的回调参数；监控同一接口 callback 值的异常变化。
