---
id: web-java-classloader-memshell-webapp-loader-selection
title: 内存马 defineClass 的落点选择：从 ServletContext 取 WebApp 类加载器，避免容器实例化 Filter 时 ClassNotFoundException
type: scenario
domain: web
path: web/java/classloader
technique: memshell-webapp-classloader-defineclass-selection
aliases:
- 内存马 ClassNotFoundException
- ApplicationFilterConfig getFilter
- ServletContext getClassLoader
- context.getLoader().getClassLoader
- defineClass 落点
- 非请求线程注入内存马
- TCCL 不可靠
tags:
- java
- classloader
- memory-shell
- tomcat
- jetty
- undertow
- servlet
- defineclass
- post-exploitation
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T09:01:01+08:00'
  notes: 已对照原文核对：ApplicationFilterConfig.getFilter 的 Tomcat5 分支、高版本 DefaultInstanceManager.classLoader=catalinaContext.getLoader().getClassLoader()、StandardContext.startInternal 创建 WebappLoader、ApplicationContext/Undertow ServletContextImpl/Jetty ContextHandler 三处 getClassLoader 实现，与卡内引用逐段一致。affected_versions 留空正确（原文未标注任何中间件版本区间，仅同时引用 Tomcat5 与高版本）。未验证点：原文为工具开发经验总结，未给出注入失败的复现日志或 ClassNotFoundException 实测，卡内 confidence medium 合理。
---

## 一句话结论

Filter/Listener 内存马注册后要由容器的 `ApplicationFilterConfig.getFilter()` 用 `context.getLoader().getClassLoader()`（WebApp 加载器）去 `loadClass` 并实例化，因此 `defineClass` 必须落在这个 WebApp 加载器上；若按常见模板用 `Thread.currentThread().getContextClassLoader()` 或系统加载器注入，在非请求线程（反序列化 gadget、定时任务）或跨应用场景下会加载不到，表现为"内存马好像打上了但一访问就 ClassNotFoundException / 500"。

## 原理

- **类身份 = 全限定名 + 定义它的 ClassLoader**：同一个类名在不同加载器下是两个不同的 `Class`。可见性只沿委托链向上（自己 → parent → bootstrap），兄弟加载器之间互相看不到对方 define 的类。
- **容器怎么加载 Filter**：Tomcat 5 的 `ApplicationFilterConfig.getFilter()` 逻辑很直白——`filterClass.startsWith("org.apache.catalina.")` 时用 `this.getClass().getClassLoader()`（容器加载器），否则用 `context.getLoader().getClassLoader()`。高版本封装成 `getInstanceManager().newInstance(filterClass)`，而 `DefaultInstanceManager` 的构造器里 `classLoader = catalinaContext.getLoader().getClassLoader()`，取值完全相同。
- **这个 loader 是什么**：`StandardContext.startInternal()` 在 `getLoader() == null` 时创建 `new WebappLoader(getParentClassLoader())` 并 `setLoader(...)`。所以它面向的是"当前 Web 应用"的类路径（`WEB-INF/classes`、`WEB-INF/lib`），parent 是容器/系统加载器。
- **为什么"平时能用"**：正常 HTTP 请求线程的 TCCL 恰好就是这个 WebApp 加载器（容器进入应用代码前设置），所以 `Thread.currentThread().getContextClassLoader()` 在请求线程里注入能成功。一旦注入发生在非请求线程——Hessian/Java 反序列化回调、Agent 的独立线程、定时任务——TCCL 可能是系统加载器、容器加载器或 `null`，此时恶意类被 define 到别处，容器用它自己的 WebApp 加载器 `loadClass` 就找不到。
- **为什么不能只依赖 `context.getClass().getClassLoader()`**：`context` 是 `StandardContext`，其加载器是容器（catalina）加载器；在高版本 JDK 的模块封装/类加载隔离下，这条路径也不保证能访问应用类，且实例化出来的类与容器期望的不是同一个。
- **规范提供的正解**：Servlet 3.0 起 `ServletContext#getClassLoader()` 返回"与该 ServletContext 关联的 Web 应用类加载器"。Tomcat 的 `ApplicationContext.getClassLoader()` 实现就是 `context.getLoader().getClassLoader()`；Undertow 的 `ServletContextImpl.getClassLoader()` 返回 `getDeploymentInfo().getClassLoader()`；Jetty 的 `ContextHandler.getClassLoader()` 返回 `_classLoader`。低版本没有该方法时，反射走 `context.getLoader().getClassLoader()`。
- **失败形态**：Filter 注册（`filterConfigs.put`）本身成功、`filterDef` 也在，但首次请求触发 `getFilter()` 时抛 `ClassNotFoundException`（可能被外层 `catch` 吞掉，日志里只有一条 warning），业务表现为 404/500 或过滤器不生效——这就是"注入成功但内存马不 work"的根因之一。

## 触发条件

- 攻击者已能在目标 JVM 执行任意代码（反序列化、表达式注入、Agent、JSP webshell），准备注入 Filter/Servlet/Listener/Valve 型内存马。
- 注入动作不在 HTTP 请求线程内（否则 TCCL 恰好正确，问题被掩盖），或目标有多个 Web 应用/多层加载器。
- 容器为 Servlet 容器（Tomcat/Jetty/Undertow/WebLogic 等），且恶意类不在应用的 `WEB-INF` 类路径上。
- 目标未启用会阻断 `defineClass` 的 RASP/SecurityManager。

## 利用步骤

1. 先定位当前应用的 `StandardContext`/`ServletContext`（线程对象图按字段名搜索，或从已注册的 Filter/Servlet 反查）。
2. 取 WebApp 类加载器：优先 `invokeMethod(context, "getClassLoader")`；抛异常则 `context.getLoader().getClassLoader()`；Undertow 走 `deploymentInfo.getClassLoader()`，Jetty 取 `_classLoader`。
3. 在该加载器上 `defineClass(name, bytes, 0, len)`（反射 `setAccessible(true)`），再 `newInstance()` 得到恶意 Filter 实例。
4. 构造 `FilterDef`（filterName、filterClass=恶意类名）与 `ApplicationFilterConfig(context, filterDef)`，放入 `context.filterConfigs`；按需补 `filterMaps`（urlPattern）。
5. 触发一次请求，确认 `getFilter()` 能实例化；若日志出现 `ClassNotFoundException`，说明落点仍是别的加载器，回到第 2 步换 loader。
6. 跨应用场景对每个 `StandardContext` 单独注入，不要假设全进程共用一份 loader。

## PoC

```java
private ClassLoader getWebAppClassLoader(Object context) {
    try {
        // Servlet 3.0+：ServletContext#getClassLoader
        return (ClassLoader) invokeMethod(context, "getClassLoader");
    } catch (Exception e) {
        // 低版本：context.getLoader().getClassLoader()
        Object loader = invokeMethod(context, "getLoader");
        return (ClassLoader) invokeMethod(loader, "getClassLoader");
    }
}

private Object getShell(Object context) throws Exception {
    ClassLoader webAppClassLoader = getWebAppClassLoader(context);
    try {
        return webAppClassLoader.loadClass(getClassName()).newInstance();
    } catch (Exception e) {
        byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
        Method defineClass = ClassLoader.class.getDeclaredMethod(
                "defineClass", byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        Class<?> clazz = (Class<?>) defineClass.invoke(
                webAppClassLoader, clazzByte, 0, clazzByte.length);
        return clazz.newInstance();
    }
}
```

对照错误写法（依赖请求线程）：

```java
ClassLoader cl = Thread.currentThread().getContextClassLoader();
if (cl == null) cl = context.getClass().getClassLoader();
// 非请求线程下 cl 往往是 system/container loader，defineClass 后 webapp 看不到
```

## 变体与关联

- **变体（容器取值）**：Tomcat `context.getLoader().getClassLoader()`；Undertow `deploymentInfo.getClassLoader()`；Jetty `_classLoader`；Spring Boot fat-jar 下可能是 `LaunchedURLClassLoader`，需按实际类型取。
- **变体（组件）**：Filter 用 WebApp loader；Servlet/Listener 同理；Valve 等容器内部组件反而要用容器加载器（`org.apache.catalina.` 前缀分支）。
- **变体（注入时机）**：Agent retransform 时由 Agent 的 `Instrumentation` 注入，仍需确认目标类的 loader；反序列化 gadget 内注入要显式携带 loader，不能靠 TCCL。
- **关联**：[[web-java-classloader-container-type-identity-memshell]]（同名类跨加载器导致 ClassCastException，与本卡同源问题）、[[java-memshell-thread-object-graph-field-search]]（定位 StandardContext）、[[web-java-classloader-deser-attach-agent-filterchain-memshell]]（反序列化+Agent 注入 FilterChain）、[[web-java-classloader-deserialization-memshell-loader-selection]]（链尾 defineClass 原语选型）。
- **边界**：目标只有一个应用且注入总在请求线程时，错误写法也能成功（问题被掩盖）；容器启用模块封装、SecurityManager 或 RASP 时 `defineClass` 可能直接被拦。

## 检测与防御

- **检测**：运行期出现对 `ClassLoader#defineClass` 的反射调用（`setAccessible` + `byte[]`）；`StandardContext.filterConfigs`/`filterDefs` 出现非部署包内的类名；`getFilter()` 抛 `ClassNotFoundException` 且类名不在 `WEB-INF`；同一 JVM 内多个应用出现同名未知类；类加载器新增来源不明的 Class。
- **防御**：启用 RASP 做动态类加载分析与恶意类扫描（检测 defineClass 调用栈、类字节特征）；限制反序列化与表达式注入入口；`SecurityManager`/模块封装收紧反射；对 `filterConfigs`、`ServletContext` 属性做完整性校验与告警；发现注入后重启实例并排查入口。
- **加固**：Filter/Servlet 注册只允许来自 `web.xml`/`web-fragment.xml`/注解，运行期变更即告警；关键应用开启类加载审计日志。
