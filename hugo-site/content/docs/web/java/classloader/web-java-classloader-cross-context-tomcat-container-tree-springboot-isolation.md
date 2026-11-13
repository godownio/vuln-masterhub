---
id: web-java-classloader-cross-context-tomcat-container-tree-springboot-isolation
title: 跨 Context/跨 Spring Boot 应用内存马排查：Tomcat 容器树枚举 StandardContext + 目标 ServletContext.getClassLoader 突破 ParallelWebappClassLoader 隔离
type: scenario
domain: web
path: web/java/classloader
technique: cross-context-memshell-scan-container-tree-classloader
tags:
- java
- tomcat
- spring-boot
- classloader
- parallelwebappclassloader
- memshell
- detection
- reflection
- cross-context
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V681
  verified_at: '2026-11-13T13:48:24+08:00'
  notes: 已对照原文与25张图核对：图20 Tomcat 架构图；图21 getAllContext 沿 Server/Service/Engine/Host 逐层 findChildren 收集 StandardContext；图22 目标 ServletContext.getClassLoader→loadClass(WebApplicationContext/RequestMappingHandlerMapping)→ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE→getAttribute→getBean→cast；图23 JSP 全部反射、未 import Spring 类；图24/25 TomcatEmbeddedContext 与 getSuperclass().getDeclaredField("filterConfigs")。修正：PoC 中 adaptedInterceptors 的声明类由 AbstractHandlerMethodMapping 改为 AbstractHandlerMapping（图18 原文反射加载的是 AbstractHandlerMapping）。原文未标注组件版本，未设 affected_versions。dedup 推荐 new，与攻击侧 Listener/Valve 注入卡非同一利用链；dup-scan 无本卡 pair。未复跑；跨应用操作只适用于可执行 Java 代码的排查场景。
url: /docs/web/java/classloader/web-java-classloader-cross-context-tomcat-container-tree-springboot-isolation/
draft: false
kb_aliases:
- 跨 context 内存马查杀
- Tomcat 容器树遍历
- Server Service Engine Host Context
- ParallelWebappClassLoader 隔离
- ServletContext getClassLoader
- Spring Boot 跨应用反射
- TomcatEmbeddedContext getSuperclass
---

## 一句话结论

一个 Tomcat 下部署多个 Web 应用时，单个应用的查杀 JSP 只能看到自己的 context；可以从当前 `StandardContext` 沿父容器 `Host → Engine → Service → Server` 遍历 `findChildren()` 拿到该 Tomcat 上所有 `StandardContext`；Spring Boot 应用之间由各自的 `ParallelWebappClassLoader` 隔离，直接强转 `WebApplicationContext` 会 `ClassCastException`，改用目标应用 `ServletContext.getClassLoader()` 取得其类加载器、再用它 `loadClass` 并反射目标 Spring 类，即可跨应用枚举/删除内存马；Spring Boot 内嵌 Tomcat 的 `TomcatEmbeddedContext` 还需要 `getSuperclass()` 才能取到 `StandardContext` 的私有字段。

## 原理

- **为什么单应用看不到别的应用**：Tomcat 的 `StandardContext` 代表一个 Web 应用，`ServletContext` 只暴露当前应用；不同应用在容器树中是兄弟节点，彼此的 `ServletContext` 不直接可见。攻击者也可能把内存马注入到同一 Tomcat 的其他 context 中以躲避只查当前应用的防守方。
- **容器树遍历**：Tomcat 层级为 `Server → Service → Engine → Host → Context`。从当前 `StandardContext.getParent()` 得到 `Host`，再 `getParent()` 得 `Engine`，通过 `Engine.getService()` 得 `Service`，`Service.getServer()` 得 `Server`；对 `server.findServices()` 的每个 Service，取 `getContainer().findChildren()` 找 Engine，再 `Engine.findChildren()` 找 Host，`Host.findChildren()` 找所有 `StandardContext`。也可直接用 `Host`/`Engine` 的 `findChildren()` 递归。
- **Spring Boot 类加载器隔离**：每个 Spring Boot 应用由独立的 `ParallelWebappClassLoader` 加载，`org.springframework.web.context.WebApplicationContext` 等类在两个 loader 下是两个不同的 `Class`；从 A 应用强转 B 应用的 context 会抛 `ClassCastException ... cannot be cast to ... (both in unnamed module of loader ParallelWebappClassLoader@...)`。
- **绕过隔离的关键**：不 import Spring 类，全部用反射；从目标应用的 `ServletContext.getClassLoader()` 取得它的 `ParallelWebappClassLoader`，用该 loader `loadClass("org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping")` 等目标类，再在目标应用的对象上反射调用 `getBean`/`getHandlerMethods`/字段访问，类型身份一致，不会 ClassCastException。
- **获取目标 Spring 上下文**：`ServletContext.getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE)` 的 key 是常量 `"org.springframework.web.context.WebApplicationContext.ROOT"`；可由目标 loader 加载的 `WebApplicationContext` 类读取该静态字段，避免在代码中引用另一个 loader 的类。拿到 context 后 `getBean(RequestMappingHandlerMapping.class)` 即可。
- **Spring Boot 内嵌 Tomcat 差异**：内嵌容器的 Context 实现是 `TomcatEmbeddedContext`（继承 `StandardContext`），`filterConfigs`、`filterDefs` 等私有字段声明在 `StandardContext`，直接 `getClass().getDeclaredField("filterConfigs")` 会 `NoSuchFieldException`；用 `standardContext.getClass().getSuperclass().getDeclaredField("filterConfigs")` 才能取到。
- **适用面**：同一思路既可用于防守方跨应用排查/删除内存马，也可被攻击者用于向同 Tomcat 的其他应用注入；本质是"用目标应用的类加载器加载目标类，再反射操作目标对象"。

## 触发条件

- 目标是一个 Tomcat（或 Spring Boot 内嵌 Tomcat）下部署多个 Web 应用/组件的环境。
- 排查者可在任一应用中执行 Java 代码（JSP、诊断接口、Arthas 等），且能反射容器/Spring 私有字段。
- 目标应用使用 `ParallelWebappClassLoader`（Spring Boot 常见）或类似隔离类加载器；无 SecurityManager/模块系统阻断。
- 需要各应用的路由/监听器基线以判断异常项。

## 利用步骤

1. 从当前请求取 `ServletContext`，反射其 `context` 字段得到当前 `StandardContext`。
2. 沿容器树向上取 `Host → Engine → Service → Server`，遍历所有 Service/Engine/Host 的 `findChildren()`，收集所有 `StandardContext`。
3. 对每个目标 context，取 `getServletContext()` 与其 `getClassLoader()`；用该 loader `loadClass` 加载 `WebApplicationContext`、`RequestMappingHandlerMapping` 等类。
4. 通过 `ServletContext.getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE)` 拿目标 Spring 上下文，反射 `getBean` 得 `RequestMappingHandlerMapping`，再按 [[defense-detection-memshell-reflection-remove-listener-controller-interceptor]] 的方法枚举/删除 Controller 与 Interceptor；Listener 走 `StandardContext` 的 `applicationEventListenersList`。
5. 若目标是 Spring Boot 内嵌 Tomcat，字段访问失败时改用 `getSuperclass()`；`TomcatEmbeddedContext` 的 `filterConfigs`/`filterDefs` 等按父类取。
6. 逐应用验证恶意路由/监听器失效，记录操作并删除查杀 JSP。

## PoC

Tomcat 容器树枚举（按原文整理）：

```java
List<StandardContext> all = new ArrayList<>();
Container host = context.getParent();
Container engine = host.getParent();
Service service = ((Engine) engine).getService();
Server server = service.getServer();
for (Service s : server.findServices()) {
    for (Container c : s.getContainer().findChildren()) {
        if (c instanceof Engine) {
            for (Container h : c.findChildren()) {
                if (h instanceof Host) {
                    for (Container ctx : h.findChildren()) {
                        if (ctx instanceof StandardContext) {
                            all.add((StandardContext) ctx);
                        }
                    }
                }
            }
        }
    }
}
```

Spring Boot 跨应用反射：

```java
ClassLoader cl = targetServletContext.getClassLoader();
Class<?> wac = cl.loadClass("org.springframework.web.context.WebApplicationContext");
String attr = (String) wac.getField("ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE").get(null);
Object appCtx = targetServletContext.getAttribute(attr);
Class<?> rhmClass = cl.loadClass(
    "org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping");
Object rhm = wac.getMethod("getBean", Class.class).invoke(appCtx, rhmClass);
Class<?> ahm = cl.loadClass("org.springframework.web.servlet.handler.AbstractHandlerMapping");
Field f = ahm.getDeclaredField("adaptedInterceptors");
f.setAccessible(true);
List<Object> interceptors = (List<Object>) f.get(rhm);
```

内嵌 Tomcat 字段：

```java
Field f = standardContext.getClass().getSuperclass().getDeclaredField("filterConfigs");
```

## 变体与关联

- **类加载器选择与类型身份**：内存马 `defineClass` 落点选择见 [[web-java-classloader-memshell-webapp-loader-selection]]；同名容器类跨 loader 的 `ClassCastException` 见 [[web-java-classloader-container-type-identity-memshell]]；本卡是其"反向使用"——主动用目标应用的 loader 加载目标类做跨应用操作。
- **无重启删除三类内存马**：Listener/Controller/Interceptor 的具体删除 API 见 [[defense-detection-memshell-reflection-remove-listener-controller-interceptor]]。
- **Arthas 单应用查杀**：[[defense-detection-tomcat-servlet-listener-valve-memshell-arthas-vmtool-remove]]；Spring Controller 检测枚举见 [[defense-detection-spring-mvc-mapping-registry-controller-memshell]]。
- **容器结构**：Tomcat Server/Service/Engine/Host/Context 层级图与生命周期可参考 Tomcat 架构文档；不同版本 `findChildren()` 返回类型与容器实现（`TomcatEmbeddedContext`）略有差异，需按实际类调整。

## 检测与防御

- **检测**：查杀 JSP/诊断接口中出现 `findServices`、`findChildren`、`ParallelWebappClassLoader`、`ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE`、`getSuperclass().getDeclaredField` 等跨应用/反射特征；异常 JSP 上传与访问日志；同一时间对多个 context 的反射访问。
- **防御**：不使用共享 Tomcat 部署不信任应用（优先一应用一实例/容器隔离）；禁用 JSP 解析与上传可写目录；应用间不要共享可执行上下文；对容器/Spring 私有字段访问做 RASP 监控；排查工具用完立即删除并审计。
- **注意**：跨应用反射会触碰其他业务对象，误删/误改可能影响多个应用，操作前备份路由/监听器清单并在测试环境验证。
