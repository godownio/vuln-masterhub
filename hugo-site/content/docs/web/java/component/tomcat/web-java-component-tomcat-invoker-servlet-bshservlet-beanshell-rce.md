---
id: web-java-component-tomcat-invoker-servlet-bshservlet-beanshell-rce
title: InvokerServlet 暴露未映射 BshServlet：/servlet/bsh.servlet.BshServlet 的 bsh.script 直接执行命令
type: scenario
domain: web
path: web/java/component/tomcat
technique: invoker-servlet-bshservlet-beanshell-rce
tags:
- java
- tomcat
- invoker-servlet
- beanshell
- bsh
- rce
- servlet
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
affected_versions: Apache Tomcat <= 6.x（InvokerServlet 前提）
verification:
  verified_by: verifier-V353
  verified_at: '2026-11-09T00:51:56+08:00'
  notes: 已对照原文核对；BshServlet doGet 读取 bsh.script 求值、exec 回显与 exec(whoami) 报文均有原文截图；与用友 U8C 卡同 sink 但入口/触发/后续不同（本卡经 InvokerServlet 暴露未映射 Servlet），dedup_review 理由成立，保留双卡；未本机复现
url: /docs/web/java/component/tomcat/web-java-component-tomcat-invoker-servlet-bshservlet-beanshell-rce/
draft: false
kb_aliases:
- InvokerServlet BshServlet RCE
- bsh.servlet.BshServlet
- BeanShell Test Servlet
- bsh.script exec
- Tomcat InvokerServlet BeanShell
- 未映射 BshServlet 利用
---

## 一句话结论

当 Tomcat 6 及更早版本启用 InvokerServlet，且应用依赖 BeanShell（`org.beanshell:bsh`）时，即使 `bsh.servlet.BshServlet` 没有在 `web.xml` 中映射，也可以直接 `POST /<ctx>/servlet/bsh.servlet.BshServlet`，用 `bsh.script=exec("whoami")` 让 BeanShell 测试 Servlet 求值并回显命令结果——InvokerServlet 的类名路由把“未映射的调试 Servlet”变成了可远程访问的 RCE 入口。

## 原理

- **入口来自类名路由**：InvokerServlet 把 `/servlet/` 后到下一个 `/` 之间的字符串当作全限定类名（这里是 `bsh.servlet.BshServlet`），在应用 classpath 中找到并转发请求，不需要该类有 `servlet-mapping`。
- **BshServlet 本身就是执行器**：`bsh.servlet.BshServlet` 是 BeanShell 自带的测试页面，`doGet` 读取 `bsh.script`、`bsh.client`、`bsh.servlet.output`、`bsh.servlet.captureOutErr` 等参数，用 BeanShell `Interpreter` 求值脚本，并把 `System.out/err` 捕获后输出到页面的 "Script Output" 区块；默认没有任何鉴权或沙箱。
- **为什么能执行系统命令**：脚本运行在 Web 容器 JVM 内，BeanShell 默认可访问 `java.lang.Runtime`/`ProcessBuilder`，`exec("whoami")` 直接派生进程，身份即 Tomcat 服务账号。
- **为什么常常存在**：企业应用为脚本化/规则计算引入 bsh 依赖后，开发往往只使用 `Interpreter` API，不会映射 BshServlet；但在 InvokerServlet 配置下，该 Servlet 随依赖一起可被调用。
- **WAF 绕过空间**：原文测试时 payload 被 WAF 拦截，作者通过 Java 字符串拼接/处理构造命令、并在 `exec` 参数中使用编码、注释等方式做“洗白”；原文未给出完整 payload，实际需按目标 WAF 规则调整。

## 触发条件

- 目标为 Tomcat 6.x 或更早，启用了 InvokerServlet 并映射 `/servlet/*`。
- 应用 classpath 中存在 BeanShell（文章环境为 bsh 2.0b4）及其 `bsh.servlet.BshServlet`。
- `/servlet/bsh.servlet.BshServlet` 可被外部访问，且 WAF 未拦截 `bsh.script` 或可绕过。
- 应用进程未被容器/沙箱限制派生进程（命令回显）。

## 利用步骤

1. **确认 InvokerServlet**：先请求一个已知 Servlet 类名或依赖中的类，确认类名路由生效。
2. **探测 BshServlet**：请求 `/<ctx>/servlet/bsh.servlet.BshServlet`，若返回标题为 "BeanShell Test Servlet" 的页面并显示 BeanShell 版本，说明该类存在。
3. **命令执行**：提交 `bsh.script=exec("whoami")`（或 `exec("cmd /c whoami")`），在 "Script Output" 查看回显。
4. **扩大利用**：用 `exec` 执行任意命令、读写文件或进一步投放 WebShell；如果 WAF 拦截，改用 Java 字符串拼接构造命令、变量拆分、编码/注释等方式绕过。
5. **稳定化**（可选）：用命令写 JSP/webshell 到可写且可解析的 web 目录，或复用 BshServlet 做后续操作。

## PoC

```http
POST /<ctx>/servlet/bsh.servlet.BshServlet HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

bsh.script=exec("whoami")
```

若存在且未拦截，响应页面包含 "BeanShell Test Servlet"、BeanShell 版本，并在 "Script Output" 中回显命令结果。

## 变体与关联

- **直接暴露的 BshServlet**：用友 U8C 等产品把 `/servlet/~ic/bsh.servlet.BshServlet` 固定映射出来，无需 InvokerServlet，属于同一 sink 的另一条入口。
- **InvokerServlet 类名路由**：本链的前置原语，负责把未映射 Servlet 暴露出来。
- **其他自带 Servlet 的依赖**：Axis2（见关联卡）、其他调试/管理 Servlet 均可按同样方式经 InvokerServlet 调用。
- **WAF 对抗**：Java 字符串处理、字符编码、BeanShell 注释与 `exec` 参数拼接。

## 检测与防御

- **移除入口**：删除 InvokerServlet 声明与 `/servlet/*` 映射，升级 Tomcat 7+。
- **剔除依赖**：生产环境移除 bsh 测试组件（或至少排除 `bsh.servlet` 包）；无法移除时用 Filter 拦截 `bsh.servlet.BshServlet`。
- **检测**：监控 `/servlet/bsh.servlet.BshServlet` 请求、`bsh.script` 参数、"BeanShell Test Servlet" 响应特征；关注 `exec(`、`Runtime`、`ProcessBuilder` 等脚本内容。
- **加固**：WAF 对 `bsh.script` 做关键字与编码检测；限制 Tomcat 服务账号权限，禁止派生进程。
