---
id: web-java-component-tomcat-invoker-servlet-class-name-routing
title: Tomcat InvokerServlet 类名路由：/servlet/<全限定类名> 直接调用未映射 Servlet（Tomcat ≤6）
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-invoker-servlet-class-name-routing
tags:
- java
- tomcat
- servlet
- invoker-servlet
- routing
- web-xml
- misconfiguration
- fingerprint
cve: []
severity: medium
confidence: high
affected_versions: Apache Tomcat <= 6.x（7.0 起移除 InvokerServlet）
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V353
  verified_at: '2026-11-09T00:51:54+08:00'
  notes: 已对照原文及24张图核对；首斜杠切分类名、拒绝 org.apache.catalina.*、Tomcat<=6 与 7.0 移除等均原文/截图印证；未本机复现
url: /docs/web/java/component/tomcat/web-java-component-tomcat-invoker-servlet-class-name-routing/
draft: false
kb_aliases:
- InvokerServlet
- org.apache.catalina.servlets.InvokerServlet
- /servlet/ 类名访问
- Servlet 类名路由
- Tomcat 6 Invoker
- 未映射 Servlet 访问
- InvokerServlet 指纹
---

## 一句话结论

Tomcat 6 及更早版本可以在 `web.xml` 中声明 `org.apache.catalina.servlets.InvokerServlet` 并映射到 `/servlet/*`；此后无需为每个 Servlet 单独写 `servlet-mapping`，直接请求 `/<ctx>/servlet/<全限定类名>` 就能调用 classpath 上任意实现了 Servlet 接口的类。该 Servlet 按 URL 中第一个 `/` 切分类名与剩余路径，并拒绝 `org.apache.catalina.*` 类。攻击者据此可以访问开发人员刻意不映射出去的脆弱 Servlet，形成“类名路由”攻击面。

## 原理

- **配置与作用**：InvokerServlet 本身是一个 Servlet（`org.apache.catalina.servlets.InvokerServlet`），在 `conf/web.xml` 或应用 `web.xml` 中声明，并映射 `/servlet/*`；同时 `context.xml` 中 Context 需要 `privileged="true"`。之后 URL 的 `/servlet/` 后一段被当作类名，由 Catalina 动态创建/查找对应 Wrapper 并转发请求。
- **源码解析逻辑**：请求路径去掉前导 `/` 后得到 `servletClass`；取其中**第一个** `/` 的位置 `slash`，把 `slash` 之前的部分作为 Servlet 类名、`slash` 之后的部分作为 `pathInfo` 传给该 Servlet。若类名以 `org.apache.catalina` 开头，直接返回 404，防止通过它访问 Tomcat 自带管理类（如 ManagerServlet 等）。
- **为什么危险**：类只需要实现 Servlet 接口、存在于 Web 应用 classpath 并且能被容器加载。开发人员经常把调试/管理/测试类 Servlet 附带在依赖里但不写映射，以为“访问不到就安全”；InvokerServlet 把“是否有映射”这层保护完全去掉。项目依赖中若含 BeanShell、Axis2 等自带 Servlet 的库，就获得直接调用入口。
- **版本限制**：该功能在 Tomcat 6 及以前支持，Tomcat 7.0 起因不安全被移除（官方改用 Servlet 3.0 的编程式注册/监听器方案）。因此黑盒遇到这种路由基本可判定为很老的 Tomcat 或自研同款实现。
- **黑盒特征**：URL 形如 `/xxx/servlet/com.xxx.XxxServlet`、`/servlet/` 后跟带点的类名，或扫描器报出“Servlet 路径可直接访问”时，应怀疑 InvokerServlet；不带参数请求一次，观察是否返回该 Servlet 的响应（而不是 404）。
- **同款实现**：一些老系统会自研类似的“InvokerServlet”（例如用友 NC 的 `/servlet/~ic/bsh.servlet.BshServlet` 路由风格），看到 `/servlet/` + 类名/前缀的路径时可以按相同思路测试。

## 触发条件

- 目标使用 Apache Tomcat 6.x 或更早版本，且应用中声明了 `InvokerServlet` 并映射到 `/servlet/*`。
- Context 配置为 `privileged="true"`，允许 InvokerServlet 访问容器内部组件。
- 目标类在 Web 应用 classpath 中、实现了 `javax.servlet.Servlet`（或 `ContainerServlet`）且不是 `org.apache.catalina.*` 包。
- 攻击者已知或能枚举出可用的全限定类名（可从开源依赖、错误信息、常见库默认 Servlet 推断）。

## 利用步骤

1. **指纹**：请求 `/<ctx>/servlet/<常见类名>`（如 `HelloServlet` 或依赖中的 Servlet 类），观察响应是否为该 Servlet 的业务输出而非 404；也可留意路径中 `/servlet/` 后带包名的 URL 特征。
2. **枚举可用类**：根据应用依赖（bsh、axis2、第三方 SDK 等）或报错栈中的包名，构造 `/<ctx>/servlet/<全限定类名>` 逐个探测；先不带参数请求，确认 Servlet 存在并观察其行为。
3. **调用目标 Servlet**：按该类自身接受的参数发起 GET/POST，触发其功能（文件读写、脚本执行、管理操作等）。
4. **组合利用**：把 InvokerServlet 当作“访问任意 Servlet 的入口”，再叠加 BeanShell、Axis2 等具体链完成 RCE。

最小配置示意（只用于说明触发条件）：

```xml
<servlet>
  <servlet-name>invoker</servlet-name>
  <servlet-class>org.apache.catalina.servlets.InvokerServlet</servlet-class>
  <load-on-startup>2</load-on-startup>
</servlet>
<servlet-mapping>
  <servlet-name>invoker</servlet-name>
  <url-pattern>/servlet/*</url-pattern>
</servlet-mapping>
```

请求示例：`GET /<ctx>/servlet/com.example.HelloServlet HTTP/1.1`，响应即 HelloServlet 的输出。

## PoC

无独立 PoC；验证请求为 `GET /<ctx>/servlet/<全限定类名>`，若返回该 Servlet 的正常响应（而非 404）即证明类名路由存在。具体 RCE 见关联的 BshServlet 与 Axis2 链卡片。

## 变体与关联

- **BeanShell 链**：`/servlet/bsh.servlet.BshServlet` 的 `bsh.script` 直接执行命令。
- **Axis2 链**：`/servlet/org.apache.axis2.webapp.AxisAdminServlet/login|upload` 借首斜杠/尾斜杠解析差异操作未映射的控制台。
- **自研同款**：用友 NC 等系统的 `/servlet/~ic/bsh.servlet.BshServlet` 路由风格；不一定真的是 Tomcat InvokerServlet，但测试思路相同。
- **Tomcat 7+ 替代实现**：通过 Servlet 3.0 `ServletContextListener`/`addServlet` 编程式注册的“新版 Invoker”，遇到时需按实际类名与路径特征判断。

## 检测与防御

- **配置排查**：在 `conf/web.xml`、应用 `web.xml`、`context.xml` 中搜索 `InvokerServlet`、`/servlet/*`、`privileged="true"`；生产环境应删除 invoker 声明与映射。
- **升级/移除**：升级到 Tomcat 7.0 及以上；无法升级时至少移除 InvokerServlet 映射并保持 Context 非 privileged。
- **检测**：WAF/日志监控 `/servlet/` 后跟带点类名的请求、对不存在的类名产生的大量 404、以及 `bsh.servlet`、`AxisAdminServlet`、`org.apache.catalina` 等关键字。
- **开发规范**：不要依赖“未映射”来保护调试/管理 Servlet；把调试组件从生产依赖中剔除。
