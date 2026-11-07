---
id: web-generic-crlf-nginx-uri-location-set-cookie
title: Nginx error_page 302 Location 拼接 $uri 未过滤：CRLF 注入 Set-Cookie 覆盖会话
type: scenario
domain: web
path: web/generic/crlf
technique: nginx-uri-location-crlf
tags:
- nginx
- crlf
- http
- header-injection
- set-cookie
- response-splitting
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T11:54:46+08:00'
  notes: 已对照原文与图07/08核对：/list/hacker 命中 error_page 404→@notfound，if ( ~ ^/list) 后 return 302 "http://$http_host/list?error_path=$uri"；原文构造 %0d%0a 注入 Set-Cookie 成功用于替换 Bot Cookie。已修正卡内失效 wikilink（web-generic-jwt-jku-allowlist-multi-at-bypass → web-generic-jwt-jku-header-hijack）。未验证点：PoC 未在本机执行；stock nginx 对 $uri 解码与 CR/LF 的处理随版本不同，卡内已注明版本差异，需按目标版本实测。frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/generic/crlf/web-generic-crlf-nginx-uri-location-set-cookie/
draft: false
kb_aliases:
- Nginx $uri CRLF
- Location 头注入
- Set-Cookie 注入
- error_page 302 注入
- Nginx 响应拆分
- CRLF 覆盖 Cookie
---

## 一句话结论

Nginx 在 `error_page` 的命名 location 中用 `return 302 "http://$http_host/list?error_path=$uri"` 拼接原始 URI 且未过滤 CR/LF 时，请求路径中的 `%0d%0a` 会被解码进 `Location` 响应头，攻击者可注入任意 `Set-Cookie`，把受害者的会话 Cookie 替换成自己的 JWT。

## 原理

- Nginx 的 `$uri` 是规范化后的请求 URI（会进行百分号解码）；把它拼进 `return 302` 的字符串后，Nginx 直接作为 `Location` 头值输出，没有对 CR/LF 做拒绝或转义。
- HTTP 头以 CRLF 分隔，头值中一旦出现 CRLF，后续字节就会被客户端解析为新的响应头。构造 `/list/x%0d%0aSet-Cookie:%20auth=<jwt>%0d%0a`，响应变成：
  ```http
  HTTP/1.1 302 Moved Temporarily
  Location: http://host/list?error_path=/list/x
  Set-Cookie: auth=<jwt>
  ```
- 浏览器/客户端收到 302 后会把注入的 `Set-Cookie` 当作合法响应头处理，写入攻击者指定的 Cookie；随后受害者（如管理 Bot）带着被替换的 JWT 访问受保护页面。
- 之所以成立：URI 是用户可控的协议字段，Nginx 配置把它跨层拼进了 HTTP 响应头；响应头解析器无法区分“原本的头”与“注入的头”。`HttpOnly` 不能阻止服务端通过 `Set-Cookie` 设置 Cookie，只能阻止 JS 读取。
- 触发还需要 404 分支：请求一个不存在的、以 `/list` 开头的路径，命中 `error_page 404 = @notfound` 与 `if ($uri ~ ^/list)`，才会走带 `$uri` 的重定向。

## 触发条件

- Nginx 配置在 `error_page`/`return 302` 的 `Location` 中拼接 `$uri`（或 `$request_uri` 等原始 URI）。
- 该分支可被未授权请求触发（如任意 404 路径）。
- Nginx/客户端未对响应头中的 CRLF 做拦截或规范化。
- 受害者是浏览器或自动化 Bot，会跟随 302 并接受 `Set-Cookie`。
- 攻击者能构造出恶意 Cookie 值（如伪造的 JWT）。

## 利用步骤

1. 确认 404 重定向行为：访问 `/<prefix>/nonexistent`，观察是否 302 到 `...?error_path=<uri>`。
2. 构造带 CRLF 的路径：`/list/hacker%0d%0aSet-Cookie:%20auth=<urlencoded-jwt>%0d%0a`（按目标是否解码选择 `%0d%0a` 或原始字节）。
3. 直接请求或诱导 Bot 访问该 URL；检查响应头中是否出现独立的 `Set-Cookie`。
4. 受害者后续请求将携带攻击者 Cookie；若该 Cookie 是伪造的管理员 JWT，即可访问管理接口或触发 XSS。
5. 与存储型 XSS 结合：先让 Bot 被替换 Cookie，再让其在同一页面执行外带脚本。

## PoC

请求（URL 编码形式）：

```http
GET /list/hacker%0d%0aSet-Cookie:%20auth%3d<JWT>%3b%20path%3d%2f%0d%0a HTTP/1.1
Host: target
```

响应（原文形态）：

```http
HTTP/1.1 302 Moved Temporarily
Server: nginx
Content-Type: text/html
Location: http://target/list?error_path=/list/hacker
Set-Cookie: auth=<JWT>; path=/
```

说明：原文在 BoneChewerCon 挑战中利用该注入把 Bot 的 `auth` Cookie 替换为伪造的 admin JWT，再配合 CSP 注入与存储型 XSS 外带 Flag；PoC 未在本会话执行。

## 变体与关联

- **其他变量**：`$request_uri`（保留原始编码，可能更易注入）、`$http_host`、`$args`、`$scheme` 等拼进响应头时同样可能注入。
- **其他头**：`Refresh`、`Content-Security-Policy`、`Link`、`Access-Control-Allow-Origin`；凡用户输入进入头值都可能响应拆分。
- **缓存组合**：若 302 响应被 CDN/反代缓存，注入的 `Set-Cookie` 可能影响更多用户（需注意缓存键与 `Set-Cookie` 处理）。
- **Nginx 版本差异**：不同版本对 `$uri` 的规范化/解码与 CRLF 处理不同；需按实际版本验证。
- 关联：[[web-generic-crlf-cfitsio-efs-http-request-header-injection]]（请求头注入）、[[web-generic-xss-csp-report-uri-claim-injection]]（同一挑战链的 CSP 绕过）、[[web-generic-jwt-jku-header-hijack]]（伪造被注入的 JWT）。

## 检测与防御

- **检测**：请求 URI 含 `%0d%0a`、`\r`、`\n`；响应头中出现重复/异常 `Set-Cookie`；302 `Location` 含用户可控路径；Bot/浏览器在访问 404 路径后 Cookie 被替换。
- **防御**：不要在 `Location` 中拼接 `$uri`/`$request_uri`；需要回显路径时改用固定页面或对值做严格 URL 编码并拒绝 CR/LF；升级到修复该行为的 Nginx 版本；在 WAF/反代层拦截含 `%0d%0a` 的请求；对敏感 Cookie 使用 `HttpOnly`、`SameSite` 并配合 CSRF 防护（不能替代头注入修复）。
