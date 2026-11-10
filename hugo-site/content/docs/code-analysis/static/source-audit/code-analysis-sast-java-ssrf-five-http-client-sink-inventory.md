---
id: code-analysis-sast-java-ssrf-five-http-client-sink-inventory
title: Java SSRF 五类 HTTP 客户端 sink 清单：URL.openConnection / fluent Request.Get / OkHttp newCall / DefaultHttpClient.execute / URL.openStream
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: java-ssrf-sink-inventory-by-http-client
tags:
- java
- ssrf
- sast
- sink-inventory
- codeql
- httpurlconnection
- okhttp
- apache-httpclient
- code-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T14:16:52+08:00'
  notes: 已对照原文核对：五类 sink 代码形态（new URL().openConnection().setRequestMethod(GET)+getResponseMessage、fluent Request.Get(String.valueOf(url)).execute().returnResponse()、com.squareup.okhttp 的 OkHttpClient/Request.Builder().get().url(url).build()/newCall().execute()、DefaultHttpClient+HttpGet+execute、url.openStream()）与原文贴出的 SSRFController 五个方法逐一对应；路径 /ssrf/one?url=http://www.baidu.com 与原文实测一致（img/01）；原文 P127.0.0.1:8888 只是靶场端口，卡片未误写为固定值。未验证点：卡片为审计方法论/清单卡，除第一类 sink 外其余四类的「服务端发起请求」未在原文实测；HttpURLConnection 的 getInputStream 排除逻辑属 CodeQL 规则细节，未写进本卡正文；未执行任何请求、未访问文中链接。
url: /docs/code-analysis/static/source-audit/code-analysis-sast-java-ssrf-five-http-client-sink-inventory/
draft: false
kb_aliases:
- Java SSRF sink 清单
- SSRF 危险 API 枚举
- HttpURLConnection SSRF
- OkHttp SSRF sink
- openStream SSRF
---

## 一句话结论

Java Web 里的 SSRF 入口取决于业务代码用哪个 HTTP 客户端：`URL.openConnection()`（HttpURLConnection）、Apache HttpClient fluent 的 `Request.Get(...).execute()`、OkHttp（v2 与 v3 包名不同）的 `newCall(...).execute()`、`DefaultHttpClient.execute(new HttpGet(...))`、以及 `URL.openStream()` 这五类调用点构成最小 sink 清单；把 controller 入口参数与这五类调用点对齐，就能快速判定某条链是否真的把用户可控字符串喂到了发起请求的位置。

## 原理

- 五类 sink 的本质相同：都接受一个字符串/URL 对象作为目标地址，并由服务端进程发起出站连接，响应或状态被返回给调用者。差别只在 API 形态与库模型：
  - `HttpURLConnection`：`new URL(t).openConnection()` 后 `setRequestMethod("GET")`、`getResponseMessage()`/`getInputStream()`。标准库，任何 JDK 环境都有。
  - Apache HttpClient fluent：`Request.Get(String.valueOf(t)).execute()`。fluent API 把 URL 直接交给执行器。
  - OkHttp（`com.squareup.okhttp`，v2）：`new OkHttpClient()` → `new Request.Builder().get().url(url).build()` → `client.newCall(request).execute()`。注意 v2 与 okhttp3 的包名/类名不同，静态规则模型往往只覆盖其一。
  - `DefaultHttpClient`（HttpClient 4.x）：`new DefaultHttpClient()` → `new HttpGet(t)` → `client.execute(get)`。sink 在 `execute` 的请求对象构造处。
  - `URL.openStream()`：等价于对 URL 发起 GET 并取字节流，是最短的一条链。
- 为什么静态分析容易漏：链路上常有 `new URL(t)`、`String.valueOf(url)` 这类"包装"调用。官方 CodeQL `RequestForgery` 用 sink 模型（`sinkNode(this, "request-forgery")`）识别这些库方法，没有建模的库（如旧版 `com.squareup.okhttp`）或 JDK 包装方法（`String.valueOf`）会成为污点传播断点，导致有漏洞但不报。
- 人工审计视角：这五类调用点可以直接当 grep 模式；对照 controller/接口参数（`@RequestParam`、`@RequestBody`、`@PathVariable`）判断是否可达，比盲信 SAST 报告更可靠。
- 原文在本地靶场（micro_service_seclab）用 `/ssrf/one?url=http://www.baidu.com` 验证了第一类 sink 确实会被服务端拉取远端页面，即"服务端替客户端访问"的基本事实。

## 触发条件

- 业务代码把用户可控字符串（请求参数、header、上传文件名中的 URL、回调地址、webhook 地址、图片/文件 URL）传给上述任一调用点；
- 没有协议白名单、域名白名单或内网地址校验（或只有可绕过的黑名单）；
- 目标服务所在网络位置具备出站能力，或能访问内网/云元数据端点。

## 利用步骤

1. 从 controller/接口层收集外部输入参数名（`url`、`imageUrl`、`callback`、`webhook`、`redirectUrl`、`feedUrl` 等）。
2. 用五类 sink 的 grep 模式反查调用点：
   ```text
   new URL( ... ).openConnection(
   new URL( ... ).openStream(
   Request.Get( ... ).execute(
   new OkHttpClient( / .newCall(
   new DefaultHttpClient( / .execute(new HttpGet(
   ```
3. 对每个命中点回溯数据来源，确认参数能原样到达（中间若有 `String.valueOf`、字符串拼接、`URI.create` 等包装，人工确认是否仍可控）。
4. 给命中点构造 `<param>=http://<dnslog>/x` 的请求，观察 DNS/HTTP 回连，确认"服务端发起请求"而非浏览器跳转。
5. 确认有回连后再升级为读内网（`/actuator`、Redis、云元数据 `169.254.169.254`）等实际危害验证。

## PoC

```http
GET /ssrf/one?url=http://<attacker-dns-log>/probe HTTP/1.1
Host: <target>
```

```http
GET /ssrf/five?url=http://<attacker-dns-log>/probe HTTP/1.1
Host: <target>
```

（路径名取自原文靶场；实际审计时按目标路由替换。只发 DNS/HTTP 回连探测，不使用协议滥用载荷做首发验证。）

## 变体与关联

- 变体：`URI.create(t)` 后再 `toURL().openConnection()`、`WebClient`/`RestTemplate`/`Feign` 等 Spring 生态客户端同样构成 sink，只是不在本卡五类内。
- 变体：包装层会改变 SAST 命中率——`String.valueOf` 断链属于模型缺失，`HostnameSanitizingPrefix` 这类 `?`/`#` 前缀会让分析器判为已净化（只能控制 query，不能控制 host），实际是否可利用要看是否能从 query 影响 host（如 `?x=http://...` 二次跳转）。
- 关联：[[code-analysis-sast-codeql-custom-taint-steps]]（补 `String.valueOf` 传播与 okhttp2 模型，正是为了扫全本卡五类 sink）。

## 检测与防御

- 检测：对上述五类调用点做代码基线扫描；在运行时监控应用进程出站的目地址，尤其是内网/元数据网段与异常 DNS 查询。
- 防御：统一封装 HTTP 出站客户端（集中做协议+主机白名单、DNS 解析后校验、禁止跟随跨域重定向、内网网段拒绝），不要在各业务点直接 new 客户端；确需允许用户自定义地址时，用"域名白名单 + 无回显 + 出站代理"模式。
