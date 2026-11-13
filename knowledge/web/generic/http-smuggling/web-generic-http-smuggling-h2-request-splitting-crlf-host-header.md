---
id: web-generic-http-smuggling-h2-request-splitting-crlf-host-header
title: HTTP/2 请求拆分（CRLF 注入）：在头值里塞入完整请求行，利用前端补齐的 \r\n\r\n 让后端把一次请求拆成两个
type: scenario
domain: web
path: web/generic/http-smuggling
technique: http2-request-splitting-crlf
aliases:
- HTTP/2 request splitting
- 请求拆分
- H2 请求拆分
- CRLF 拆分请求
- host 头位置
tags:
- http2
- request-splitting
- crlf-injection
- response-queue-poisoning
- host-header
- desync
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V609
  verified_at: '2026-11-12T19:38:49+08:00'
  notes: 已对照原文12691「请求拆分」节及截图31-38核对：GET /x返回404、Inspector中foo头值bar\r\n\r\nGET /x HTTP/1.1\r\nHost:...、前端降级追加\r\n\r\n补全注入请求、捕获管理员302+Set-Cookie、/my-account与/admin、删除carlos、Solved；Host头位置问题(前端把新Host追加到foo之后导致第一个请求缺Host，需自行在拆分点前写Host)与原文重写请求小节一致。dedup：除自身外最高相关为同文H2.TE/CRLF-TE/隧道及H2.CL卡，均按注入内容与利用方式区分；库内HTTP/1走私卡(CL.0、未知TE、Varnish、HAProxy等)不同链。原子。原文未给产品版本，保持省略；未在本机复现。
---

## 一句话结论

HTTP/2 头值中的 `\r\n` 在降级为 HTTP/1.1 时会变回头部分隔符；把 `\r\n\r\nGET /x HTTP/1.1\r\nHost: ...` 注入任意头值，前端在重建请求时又会在头部末尾补上 `\r\n\r\n`，两段拼起来就让后端把"一个 H2 请求"拆成两个完整 HTTP/1 请求——拆分点发生在头部而不是 body，甚至 GET 请求也能用于响应队列中毒和会话捕获。

## 原理

- HTTP/2 头部是二进制键值对，值内的 CRLF 不具分隔语义；前端降级时按文本重建 HTTP/1 头，若未清理值内 CRLF，`\r\n` 就重新变成结构。
- 与"走私一个前缀"不同，请求拆分注入的是一个完整请求：`头名: 任意值\r\n\r\nGET /x HTTP/1.1\r\nHost: TARGET`。前端重建时在头部块末尾追加 `\r\n\r\n` 作为结束，正好补全注入请求的结尾，使后端看到两个请求。
- 关键细节是 Host 头的位置：降级时前端常把 `:authority` 转成新的 `Host` 头并追加到头部列表末尾。如果拆分点在 `foo` 头值中，前端追加的 Host 会落在第二个（注入的）请求里，导致第一个请求没有 Host。因此要在注入内容中自己写出 `Host:`，把第一个请求补齐。
- 为什么成立：前端把注入内容整体当作"一个头的值"做检查，安全检查看到的是一段字符串；后端重新解析时这段字符串变成了请求行和头，检查与使用发生结构转换，边界被攻击者控制。
- 与 body 内拆分的区别：拆分在头部，可以只用 GET；注入的第二个请求不需要依赖后续请求体，因此更稳定，也更容易与响应队列中毒结合。

## 触发条件

- 前端接受 HTTP/2 并降级为 HTTP/1.1。
- 前端不拒绝头值中的 CRLF，且会为请求补 `\r\n\r\n` 与 Host。
- 后端把 CRLF 当作头/请求分隔符。
- 前后端连接复用，拆分出的第二个请求能影响后续响应队列。
- 攻击者可用原始 H2 工具编辑头值。

## 利用步骤

1. Burp 切 HTTP/2，关闭 Update Content-Length，选一个不存在的路径（如 `/x`）以便用 404 区分正常与捕获响应。
2. 添加任意头，名 `foo`，值：
   `bar\r\n\r\nGET /x HTTP/1.1\r\nHost: TARGET`
3. 发送后正常请求应返回 404/异常，说明注入的请求已进入后端连接。
4. 观察后续响应，捕获管理员登录产生的 `302 Found`、`Location: /my-account?id=administrator` 与 `Set-Cookie: session=...`。
5. 用该 Cookie 访问 `/my-account?id=administrator` 与 `/admin`，找到 `/admin/delete?username=carlos` 并调用删除用户，完成利用。
6. 若前端追加 Host 的位置导致第一个请求缺 Host，把头值改为在拆分点前显式带 `Host: TARGET\r\n`，保证两个请求都完整。

## PoC

```http
GET /x HTTP/2
Host: TARGET
foo: bar\r\n
\r\n
GET /x HTTP/1.1\r\n
Host: TARGET
```

```http
# 捕获到的管理员响应
HTTP/2 302 Found
Location: /my-account?id=administrator
Set-Cookie: session=<admin-session>; Secure; HttpOnly; SameSite=None
```

说明：PoC 为原文请求拆分靶场流程的结构化复现，`\r\n` 需作为头值真实字节发送，域名与会话值已泛化；未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：拆分点可放在头名称而非头值；也可注入 CLI 请求行 + 完整头，构造任意方法/路径。
- 变体：与缓存投毒结合，把拆分出的响应写入缓存；或用 `:path` 伪头注入实现类似的隧道效果。
- 关联：[[web-generic-http-smuggling-h2-crlf-header-value-te-bypass]]（头值 CRLF 注入 TE）、[[web-generic-http-smuggling-h2-response-queue-poisoning-session-capture]]（拆分后的主要危害）、[[web-generic-http-smuggling-h2-request-tunnelling-access-control-bypass]]（另一种隐藏在响应体中的请求）。
- 边界：前端清理头值 CRLF、拒绝异常头、或按 H2 语义重建请求而不做文本拼接时，本链不成立。

## 检测与防御

- 检测：H2 头值中出现 CR/LF；后端看到来源不明的请求行/重复 Host；同一连接请求数多于前端记录；异常 404 与响应错配。
- 防御：拒绝头名/头值中的 CR、LF、NUL；H2→H1 转换使用结构化解析而非字符串拼接；Host 由转换层统一生成并校验唯一性。
- 加固：端到端 HTTP/2；反代/CDN 升级；WAF 检测 H2 头值换行与异常请求拆分；监控响应队列异常。
