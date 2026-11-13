---
id: defense-detection-memshell-reflection-remove-listener-controller-interceptor
title: 内存马无重启查杀：反射重建 Tomcat applicationEventListenersList、Spring unregisterMapping 删 Controller、adaptedInterceptors 删拦截器
type: scenario
domain: defense
path: defense/detection
technique: reflection-memshell-remove-listener-controller-interceptor
tags:
- java
- tomcat
- spring
- spring-mvc
- memshell
- detection
- incident-response
- reflection
- unregister-mapping
- adapted-interceptors
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V681
  verified_at: '2026-11-13T13:48:22+08:00'
  notes: 已对照原文与25张图核对：图01-04 listenerStart→setApplicationEventListeners（applicationEventListenersList.clear+addAll）源码；图05 getDeclaredField 失败回退 getSuperclass；图06 过滤后 setApplicationEventListeners 重建列表；图11-15 lookupHandlerMethod/getHandlerMethods/unregisterMapping（mappingRegistry.unregister 清 registry、directPaths/pathLookup、mappingName、corsLookup）；图16-19 getHandlerExecutionChain 遍历 adaptedInterceptors 及 iterator.remove 删除；图07 old_spring.jsp?cmd=whoami 演示与图08-10 工具列表/删除 UI。修正：拦截器字段 adaptedInterceptors 声明在 AbstractHandlerMapping 而非 AbstractHandlerMethodMapping（图18 反射加载的正是 AbstractHandlerMapping），已改正文3处与 PoC；并把“该字段不是 final”修正为“字段引用通常为 final、指向的 ArrayList 可变未做不可变包装”。dedup 与攻击侧 web-java-component-tomcat-listener-memshell 等为相反方向/不同操作，非同一利用链，append_scenario 成立；dup-scan 无本卡 pair。未复跑 PoC（工具未开源，删除效果由原文截图与源码佐证）；跨版本字段名差异未逐一验证。
url: /docs/defense/detection/defense-detection-memshell-reflection-remove-listener-controller-interceptor/
draft: false
kb_aliases:
- 内存马查杀
- Memshell_Kill
- Tomcat Listener 内存马删除
- setApplicationEventListeners
- Spring Controller 内存马删除
- unregisterMapping
- adaptedInterceptors 删除
---

## 一句话结论

对 Tomcat Listener、Spring Controller、Spring Interceptor 三类内存马，可在不重启的情况下用反射读取并改写容器的真实运行期注册表：取出 `StandardContext.applicationEventListenersList` 过滤掉恶意 Listener 后调用 `setApplicationEventListeners` 重建列表、对 `AbstractHandlerMethodMapping` 调用 `unregisterMapping` 注销恶意 Controller、从 `AbstractHandlerMapping` 的 `adaptedInterceptors` 列表中直接删除恶意拦截器，使恶意路由/监听器立即失效。

## 原理

- **Tomcat Listener 注册表**：`StandardContext.listenerStart` 先由 `findApplicationListeners` 从 web.xml/注解取监听器类名，`InstanceManager.newInstance` 实例化，最后调用 `setApplicationEventListeners(Object[])`。该方法实现是 `applicationEventListenersList.clear()` 后再 `addAll`，即用传入数组整体替换列表。攻击者注入的 Listener 内存马同样会进入 `applicationEventListenersList`；反射拿到该字段，按类名/类加载器过滤掉恶意对象后，再用剩余对象数组反射调用 `setApplicationEventListeners`，即可让恶意 Listener 从容器注册表中消失。
- **为什么不直接删列表**：`applicationEventListenersList` 是容器内部字段，不同 Tomcat 版本实现（CopyOnWriteArrayList）与生命周期事件可能依赖整体重建；原文选择先过滤再调用容器自己的 setter 重建，避免只改字段导致状态不一致。Spring Boot 内嵌 Tomcat 的 Context 是 `TomcatEmbeddedContext`（`StandardContext` 子类），字段在父类上，需要 `getSuperclass().getDeclaredField(...)`。
- **Spring Controller 注册表**：`DispatcherServlet.getHandler → getHandlerInternal → lookupHandlerMethod` 从 `AbstractHandlerMethodMapping.mappingRegistry` 取路由。`getHandlerMethods()` 把 `mappingRegistry.getRegistrations()` 转成 `Map<RequestMappingInfo, HandlerMethod>`，可枚举 URL→类#方法；删除时调用 `unregisterMapping(mapping)`，内部 `mappingRegistry.unregister(mapping)` 会移除 `registry` 条目、按 directPaths 清理 `pathLookup`、移除 mappingName 与 corsLookup，路由立即不再匹配。
- **Spring 拦截器注册表**：`getHandlerExecutionChain` 遍历 `adaptedInterceptors`，对 `MappedInterceptor` 判断 matches 后加入执行链。反射 `AbstractHandlerMapping.adaptedInterceptors`（字段声明在 `AbstractHandlerMapping`，不是 `AbstractHandlerMethodMapping`；在 `RequestMappingHandlerMapping` 实例上取值）得到 List，直接 `remove`/`iterator.remove()` 恶意拦截器即可；字段引用本身通常是 final，但指向的 `ArrayList` 未做不可变包装，可原地修改（无需重新赋值字段）。
- **为什么无重启生效**：三者都是请求分发路径上实时读取的注册表，删除后下一次请求就不再命中；不需要卸载类或重启容器，适合不能停机的关键业务。
- **前提与风险**：需要有 Java 代码执行能力（JSP 上传、诊断接口、Arthas 等）和反射权限；需要基线判断哪些条目异常；误删正常 Listener/Controller/Interceptor 会影响业务，操作前应记录清单并先在测试环境验证。

## 触发条件

- 目标为 Tomcat/Spring MVC 应用，攻击者已注入 Listener/Controller/Interceptor 型内存马。
- 排查者能在应用中执行 Java 代码（如上传查杀 JSP 到可解析目录）或通过 Arthas/Actuator 等价执行。
- 反射访问容器私有字段未被模块系统/安全管理器阻断（常规 Spring 应用在 unnamed module，可反射）。
- 已掌握应用正常监听器/路由/拦截器基线，能区分恶意项。

## 利用步骤

1. 在任一可解析 JSP 的目录上传查杀 JSP（或通过 Arthas 等执行同等反射代码）。
2. **Listener**：从当前请求取 `StandardContext`，反射 `applicationEventListenersList`（失败时尝试父类字段），打印每个 Listener 的类名/类加载器/资源路径，过滤恶意项后用剩余数组反射调用 `setApplicationEventListeners(Object[])` 重建。
3. **Controller**：获取 `RequestMappingHandlerMapping` 实例，反射调用 `getHandlerMethods()` 列出 `RequestMappingInfo → HandlerMethod`；对照源码/基线定位恶意 controller，按对应 key 反射调用 `unregisterMapping(mapping)` 注销。
4. **Interceptor**：反射 `AbstractHandlerMapping.adaptedInterceptors` 得到列表，按类名/`toString` 过滤并 `remove` 恶意拦截器。
5. 访问原内存马 URL、触发 Listener 行为、走一遍业务路由，确认恶意组件失效且正常业务未受影响；删除查杀 JSP。

## PoC

Listener 清理（示意，需按实际 ctx 获取方式补全）：

```java
Field f = StandardContext.class.getDeclaredField("applicationEventListenersList");
f.setAccessible(true);
List<Object> list = (List<Object>) f.get(ctx);
list.removeIf(o -> o.getClass().getName().contains("memshell"));
Method m = StandardContext.class.getMethod("setApplicationEventListeners", Object[].class);
m.invoke(ctx, (Object) list.toArray());
```

Controller 清理：

```java
Method getHandlerMethods = AbstractHandlerMethodMapping.class.getMethod("getHandlerMethods");
Map<Object, HandlerMethod> handlers = (Map<Object, HandlerMethod>) getHandlerMethods.invoke(mapping);
// 过滤恶意 HandlerMethod 对应的 key
Method unregister = AbstractHandlerMethodMapping.class.getMethod("unregisterMapping", Object.class);
unregister.invoke(mapping, maliciousKey);
```

Interceptor 清理：

```java
Field f = AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");
f.setAccessible(true);
List<Object> interceptors = (List<Object>) f.get(requestMappingHandlerMapping);
interceptors.removeIf(o -> o.toString().contains("memshell"));
```

Spring Boot 内嵌 Tomcat 字段兼容：

```java
Field f = standardContext.getClass().getSuperclass().getDeclaredField("filterConfigs");
```

## 变体与关联

- **同目标其他查杀路径**：Arthas vmtool 查杀 Tomcat Servlet/Listener/Valve（`applicationEventListenersList.remove`、`removeServletMapping`、`removeValve`）见 [[defense-detection-tomcat-servlet-listener-valve-memshell-arthas-vmtool-remove]]；Spring Controller 仅检测枚举见 [[defense-detection-spring-mvc-mapping-registry-controller-memshell]]；Filter/ProxyValve/WebSocket/Upgrade 等查杀卡见 defense/detection 目录。
- **攻击侧对照**：动态 Controller 内存马见 [[web-java-framework-spring-mvc-dynamic-controller-memshell]]；拦截器内存马见 [[web-java-framework-spring-mvc-interceptor-memshell]]；知道注入点才能准确定位注册表。
- **跨应用排查**：同一 Tomcat 多应用/Spring Boot 隔离的跨 Context 扫查见 [[web-java-classloader-cross-context-tomcat-container-tree-springboot-isolation]]。
- **工具形态**：原文工具借鉴 java-memshell-scanner，使用 JSP 上传后在页面操作；查杀 JSP 本身也是攻击面，用完应删除。

## 检测与防御

- **检测**：容器内出现异常 Listener/Controller/Interceptor 类名、无源码/无资源文件的类、`RequestMappingInfo` 指向动态注册类；JSP 查杀工具本身的上传与访问日志；`setApplicationEventListeners`/`unregisterMapping` 等反射调用（可通过 RASP/字节码监控）。
- **防御**：禁止生产环境上传 JSP、限制可解析目录写权限；对应用做启动基线（监听器/路由/拦截器清单）并定期比对；使用 RASP/Agent 监控运行时注册表变更；关键业务部署多实例时逐台核查；查杀操作前备份清单，避免误删。
