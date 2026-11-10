---
id: web-java-framework-undertow-managedfilter-threadlocal-lifecycle-locate
title: Undertow 运行中定位任意 Filter 实例：当前线程 ThreadLocalMap → ServletRequestContext → deployment.lifecycleObjects → ManagedFilter.filter
type: scenario
domain: web
path: web/java/framework
technique: undertow-managedfilter-threadlocal-lifecycle-reflection
tags:
- java
- undertow
- memshell
- reflection
- threadlocal
- servlet
- filter
- locate
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:42:02+08:00'
  notes: 已对照原文与图02/03/04核对：调用栈中 doFilter:90 JFinalFilter → doFilter:67 ManagedFilter(io.undertow.servlet.core) → FilterHandler/ServletInitialHandler 与卡内 Undertow 容器定位链一致；图04 显示 JFinalFilter 的 handler 链 DemoHandler→Demo2Handler→Demo3Handler→ActionHandler 及各节点 actionMapping 字段，支撑从 ServletRequestContext→deployment.lifecycleObjects→ManagedFilter.filter 取实例的可行性。卡内 PoC 为按原文 static 块整理的可复用版本（含逐级父类 getField 兜底，原文 getField 亦是该写法）。未验证点：未在 JFinal/Undertow 环境复跑反射链；字段名 deployment/lifecycleObjects 依赖 Undertow 版本，卡内已注明。
url: /docs/web/java/framework/web-java-framework-undertow-managedfilter-threadlocal-lifecycle-locate/
draft: false
kb_aliases:
- Undertow ManagedFilter 反射
- ServletRequestContext deployment lifecycleObjects
- threadLocals table Entry value
- 从线程取容器 Filter 实例
- Undertow 内存马定位
---

## 一句话结论

在 Undertow（含 jfinal-undertow、Spring Boot Undertow 等）处理请求的线程里，`Thread.currentThread().threadLocals` 的 `table` 中会有一个 `value` 是 `io.undertow.servlet.handlers.ServletRequestContext`；该对象的 `deployment` 字段是一条 `DeploymentImpl`，其 `lifecycleObjects` 列表里放着本次部署注册的所有 `ManagedFilter`，每个 `ManagedFilter` 的 `filter` 字段就是真实 `Filter` 实例——顺着这一跳跳反射即可在运行时拿到任意容器 Filter（如 `JFinalFilter`），是插入各类"框架级内存马"的公共入口。

## 原理

- **为什么当前线程一定持有请求上下文**：Undertow 的 `ServletRequestContextThreadSetupAction` 在请求进入时把 `ServletRequestContext` 放进 `ThreadLocal`（`HttpServerExchange` 与请求对象的关联），处理线程执行业务代码时，该值仍在 `ThreadLocalMap` 里可达。
- **ThreadLocalMap 的结构**：`Thread.threadLocals` 是 `ThreadLocal.ThreadLocalMap`，内部 `table` 是 `Entry[]` 数组，每个 `Entry` 有 `value` 字段（弱引用的是 key）。遍历数组按类名过滤即可找到目标上下文，不需要知道具体是哪个 ThreadLocal 实例。
- **deployment 与 lifecycleObjects**：`ServletRequestContext.getDeployment()` 拿到的 `Deployment`（实现类 `DeploymentImpl`）持有 `lifecycleObjects`（`List<Lifecycle>`），Undertow 把所有生命周期对象（servlet、filter、listener 包装器）都晒在这里，因此不必遍历 servletContext 的属性。
- **ManagedFilter 是包装层**：Undertow 用 `ManagedFilter` 包住用户注册的 `Filter`（持有 `filter` 字段与 `FilterConfig`），所以拿到 `ManagedFilter` 再取 `filter` 得到的是框架自己 new 出来的那个实例——正是内存马需要修改的对象（改它的 `next`、`config` 或内部字段）。
- **通用性**：这条链不依赖具体框架（JFinal/Spring/自研），只依赖 Undertow 的部署结构；取到 Filter 之后做什么由各框架的"下一跳"决定（例如 JFinal 的 `JFinalFilter` 里有 `jfinal`/`handler` 字段，可继续取 `ActionMapping`）。
- **代价与边界**：反射需要处理继承层级（字段可能声明在父类，本例用 `getDeclaredField` + 逐级 `getSuperclass` 兜底）；`deployment`/`lifecycleObjects` 字段名在 Undertow 不同版本可能有差异，需按版本核对；若目标不是 Undertow（Tomcat/Jetty/Netty），该入口不成立，要换对应容器的线程上下文。

## 触发条件

- 目标容器为 Undertow（`io.undertow.servlet`、`io.undertow.server` 在 classpath，常见于 jfinal-undertow、`spring-boot-starter-undertow`）。
- 攻击者已能在 JVM 内执行 Java 代码，且执行点位于处理 HTTP 请求的线程（反序列化、表达式注入、已有 webshell 均满足）。
- 目标未启用强模块化限制（JDK 9+ 下对 `java.lang.Thread` 的私有字段反射需要 `--add-opens java.base/java.lang=ALL-UNNAMED`，否则 `setAccessible(true)` 抛 `InaccessibleObjectException`；JDK 8 无此问题）。

## 利用步骤

1. 确认容器：错误页/响应头出现 `Undertow`、或 classpath 有 `io.undertow.servlet.core.ManagedFilter`。
2. 在请求线程内取 `Thread.currentThread()`，反射读 `threadLocals`，再读 `table`（`Entry[]`）。
3. 遍历数组，对每个非空 `Entry` 取 `value`，用 `value.getClass().getName().contains("ServletRequestContext")` 过滤。
4. 命中后取 `deployment`，再取 `lifecycleObjects`（`List<Lifecycle>`），遍历找到类名含 `ManagedFilter` 的元素，反射读 `filter` 得到 `Filter` 实例。
5. 拿 `Filter` 实例后按框架继续：JFinal 取 `JFinalFilter` 的 `jfinal`/`handler`；Spring 可取 `DelegatingFilterProxy` 的 `delegate`；自研框架按其字段继续。
6. 把这条链固化成不依赖调试器的反射代码，并做异常兜底（字段找不到时逐级父类查找）。

## PoC

```java
public static Object getField(Object o, String name) throws Exception {
    Class<?> c = o.getClass();
    while (c != null) {
        try {
            Field f = c.getDeclaredField(name);
            f.setAccessible(true);
            return f.get(o);
        } catch (NoSuchFieldException e) {
            c = c.getSuperclass();
        }
    }
    return null;
}

public static Object findManagedFilter() throws Exception {
    Object thread = Thread.currentThread();
    Object threadLocals = getField(thread, "threadLocals");
    Object table = getField(threadLocals, "table");          // Entry[]
    Object result = null;
    if (table != null) {
        for (int i = 0; i < Array.getLength(table); i++) {
            Object entry = Array.get(table, i);
            if (entry == null) continue;
            Object value = getField(entry, "value");
            if (value != null && value.getClass().getName().contains("ServletRequestContext")) {
                Object deployment = getField(value, "deployment");
                java.util.List<?> lifecycle = (java.util.List<?>) getField(deployment, "lifecycleObjects");
                for (Object o : lifecycle) {
                    if (o != null && o.getClass().getName().contains("ManagedFilter")) {
                        result = getField(o, "filter");          // 真实 Filter 实例
                    }
                }
                break;
            }
        }
    }
    return result;
}
```

```text
# 典型命中路径（调试器里看到的结构）
Thread → threadLocals → table → [i] → value = {ServletRequestContext}
       → deployment = {DeploymentImpl} → lifecycleObjects = {List}
       → [{ManagedFilter}] → filter = {JFinalFilter}
```

```text
# JDK 9+ 启动参数（若反射被模块系统拦截）
--add-opens java.base/java.lang=ALL-UNNAMED
--add-opens java.base/java.lang.reflect=ALL-UNNAMED
```

## 变体与关联

- 变体：不遍历 `lifecycleObjects`，改读 `DeploymentImpl` 的 `servletContext` 属性表（`attributes`）里的 `ManagedFilter` 链；或直接读 `HttpServerExchange` 的 `filterChain`（`ServletContextImpl` 里的 `FilterChainImpl`）。
- 变体：容器换成 Tomcat 时改走 `ThreadLocal` 中的 `Request`→`StandardContext`→`filterConfigs`；Jetty 走 `HttpConnection`/`ServletContextHandler` 字段。
- 关联：[[web-java-framework-jfinal-actionmapping-route-memshell]]（取到 `JFinalFilter` 后拼 `Action` 注册路由）、[[web-java-framework-jfinal-action-interceptors-field-memshell]]（改现有 `Action` 的 `interceptors`）、[[web-java-framework-jfinal-handler-next-chain-memshell]]（改 `Handler.next` 链）、[[java-memshell-thread-object-graph-field-search]]（按字段名 BFS 自动找注册表的通用定位思路）。
- 边界：非 Undertow 容器、JDK 9+ 未 `--add-opens`、字段名随版本变化、执行点不在请求线程（如定时任务/异步回调线程无 `ServletRequestContext`）时失败；异步线程池里需要回到处理线程或改用静态引用。

## 检测与防御

- 检测：运行期出现对 `Thread.threadLocals`/`ThreadLocalMap.table` 的反射访问（RASP 可挂钩 `Field.get` 与 `setAccessible`）；`jdk.internal.reflect`/`--add-opens` 异常；类名过滤字符串 `ServletRequestContext`、`ManagedFilter` 出现在可疑 class 常量池。
- 加固：JDK 17+ 保持强封装（不加 `--add-opens java.base/java.lang`）；容器升级后核对 `DeploymentImpl`/`ManagedFilter` 字段；生产 JVM 开启 `-Djdk.reflect.useDirectMethodHandle=false` 仅作干扰，非根治。
- 应急：发现内存马后从 `lifecycleObjects` 顺链枚举所有 `ManagedFilter.filter`，逐个比对是否为上线包内的原始类（哈希/文件名），异常项即注入点；同时检查 `Handler.next` 链与 `Action.mapping`。
- 修复思路：内存马的根治在"阻断写入原始"（不可信反序列化/表达式/文件写），运行期只能检测与重启恢复。
